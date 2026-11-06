//! Reversible configuration changes.
//!
//! Teardown must always restore routes, DNS, MTU and the device, including on
//! panic or Ctrl-C. [`Session`] records every
//! applied change and applies its inverse in reverse order when
//! [`Session::rollback`] runs or when the session is dropped.
//!
//! Rollback is idempotent: a second call and the drop handler both observe an
//! empty undo stack.

use std::net::IpAddr;

use crate::error::TunError;
use crate::route::Route;

/// A configuration change that can be inverted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Address/prefix changed from `old` to `new`.
    SetAddr {
        /// Previous value.
        old: Option<(IpAddr, u8)>,
        /// New value.
        new: Option<(IpAddr, u8)>,
    },
    /// MTU changed from `old` to `new`.
    SetMtu {
        /// Previous value.
        old: Option<u16>,
        /// New value.
        new: Option<u16>,
    },
    /// The whole route set changed.
    SetRoutes {
        /// Previous set.
        old: Vec<Route>,
        /// New set.
        new: Vec<Route>,
    },
    /// The DNS server set changed.
    SetDns {
        /// Previous set.
        old: Vec<IpAddr>,
        /// New set.
        new: Vec<IpAddr>,
    },
    /// One route was added.
    AddRoute(Route),
    /// One route was removed.
    RemoveRoute(Route),
}

impl Change {
    /// The change that undoes this one.
    pub fn inverse(&self) -> Self {
        match self {
            Self::SetAddr { old, new } => Self::SetAddr {
                old: *new,
                new: *old,
            },
            Self::SetMtu { old, new } => Self::SetMtu {
                old: *new,
                new: *old,
            },
            Self::SetRoutes { old, new } => Self::SetRoutes {
                old: new.clone(),
                new: old.clone(),
            },
            Self::SetDns { old, new } => Self::SetDns {
                old: new.clone(),
                new: old.clone(),
            },
            Self::AddRoute(route) => Self::RemoveRoute(route.clone()),
            Self::RemoveRoute(route) => Self::AddRoute(route.clone()),
        }
    }
}

/// What happened when a recorded change was undone during recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndoOutcome {
    /// The inverse ran and the change was undone.
    RolledBack,
    /// The state the inverse would remove was already absent.
    AlreadyAbsent,
}

/// Applies [`Change`] values to a TUN device or a platform shim.
pub trait RollbackBackend {
    /// Apply one change.
    fn apply(&mut self, change: &Change) -> Result<(), TunError>;

    /// Whether the recorded device/interface alias currently exists.
    ///
    /// A hard kill on Windows also removes the WinTun adapter, so every
    /// device-scoped journal entry is already undone. The default is `true`
    /// for backends that have no such concept.
    fn device_present(&mut self) -> Result<bool, TunError> {
        Ok(true)
    }

    /// Apply the inverse of a recorded change, classifying already-absent
    /// state separately from a real rollback.
    fn undo(&mut self, change: &Change) -> Result<UndoOutcome, TunError> {
        self.apply(&change.inverse())?;
        Ok(UndoOutcome::RolledBack)
    }
}

/// Records changes and can undo them in reverse order.
pub struct Session<B: RollbackBackend> {
    backend: B,
    undo: Vec<Change>,
    closed: bool,
}

impl<B: RollbackBackend> Session<B> {
    /// Wrap a backend.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            undo: Vec::new(),
            closed: false,
        }
    }

    /// Apply a change and remember its inverse.
    ///
    /// A failed backend operation is not recorded, because it had no effect.
    pub fn apply(&mut self, change: Change) -> Result<(), TunError> {
        self.backend.apply(&change)?;
        self.undo.push(change);
        Ok(())
    }

    /// Undo every recorded change in reverse order.
    ///
    /// All inverses are attempted even if one fails; the first error is
    /// returned after the stack is empty. A second call is a no-op.
    pub fn rollback(&mut self) -> Result<(), TunError> {
        self.closed = true;
        let mut first_error = None;
        while let Some(change) = self.undo.pop() {
            // `undo` treats an already-absent target as success, so a hard kill
            // that removed the adapter cannot make an otherwise clean teardown
            // fail.
            if let Err(error) = self.backend.undo(&change) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Borrow the backend (used by tests and by the doctor probe).
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Whether rollback has run.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

impl<B: RollbackBackend> Drop for Session<B> {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.rollback();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use std::rc::Rc;

    fn dns(octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 251, 3, octet))
    }

    fn route(octet: u8) -> Route {
        Route::on_link(IpAddr::V4(Ipv4Addr::new(10, 0, octet, 0)), 16).expect("route")
    }

    #[derive(Clone, Default)]
    struct Recorder {
        applied: Rc<RefCell<Vec<Change>>>,
    }

    impl Recorder {
        fn applied(&self) -> Vec<Change> {
            self.applied.borrow().clone()
        }
    }

    impl RollbackBackend for Recorder {
        fn apply(&mut self, change: &Change) -> Result<(), TunError> {
            self.applied.borrow_mut().push(change.clone());
            Ok(())
        }
    }

    #[test]
    fn rollback_runs_in_reverse_order() {
        let recorder = Recorder::default();
        let mut session = Session::new(recorder.clone());

        let mtu = Change::SetMtu {
            old: None,
            new: Some(1396),
        };
        let dns_change = Change::SetDns {
            old: vec![],
            new: vec![dns(18)],
        };
        let added = Change::AddRoute(route(1));

        session.apply(mtu.clone()).expect("mtu");
        session.apply(dns_change.clone()).expect("dns");
        session.apply(added.clone()).expect("route");
        session.rollback().expect("rollback");

        let applied = recorder.applied();
        assert_eq!(applied.len(), 6, "three forward and three inverse changes");
        assert_eq!(applied[0], mtu);
        assert_eq!(applied[1], dns_change);
        assert_eq!(applied[2], added);

        assert_eq!(applied[3], Change::RemoveRoute(route(1)));
        assert_eq!(
            applied[4],
            Change::SetDns {
                old: vec![dns(18)],
                new: vec![]
            }
        );
        assert_eq!(
            applied[5],
            Change::SetMtu {
                old: Some(1396),
                new: None
            }
        );
    }

    #[test]
    fn rollback_is_idempotent() {
        let recorder = Recorder::default();
        let mut session = Session::new(recorder.clone());
        session.apply(Change::AddRoute(route(2))).expect("apply");

        session.rollback().expect("first");
        session.rollback().expect("second");
        session.rollback().expect("third");

        assert!(session.is_closed());
        let applied = recorder.applied();
        assert_eq!(applied.len(), 2, "one forward and one inverse only");
        assert_eq!(applied[1], Change::RemoveRoute(route(2)));
    }

    #[test]
    fn drop_rolls_back() {
        let recorder = Recorder::default();
        {
            let mut session = Session::new(recorder.clone());
            session.apply(Change::AddRoute(route(3))).expect("apply");
            assert!(!session.is_closed());
        }

        let applied = recorder.applied();
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[1], Change::RemoveRoute(route(3)));
    }

    #[test]
    fn failed_apply_is_not_recorded() {
        struct Failing;
        impl RollbackBackend for Failing {
            fn apply(&mut self, change: &Change) -> Result<(), TunError> {
                if matches!(change, Change::AddRoute(_)) {
                    Err(TunError::Permission("denied".into()))
                } else {
                    Ok(())
                }
            }
        }

        let mut session = Session::new(Failing);
        assert!(session.apply(Change::AddRoute(route(4))).is_err());
        session.rollback().expect("nothing to undo");
        assert!(session.is_closed());
    }

    #[test]
    fn rollback_treats_an_already_absent_target_as_success() {
        struct AlreadyAbsent;
        impl RollbackBackend for AlreadyAbsent {
            fn apply(&mut self, _change: &Change) -> Result<(), TunError> {
                Ok(())
            }

            fn undo(&mut self, _change: &Change) -> Result<UndoOutcome, TunError> {
                Ok(UndoOutcome::AlreadyAbsent)
            }
        }

        let mut session = Session::new(AlreadyAbsent);
        session.apply(Change::AddRoute(route(7))).expect("apply");
        session.rollback().expect("already absent is success");
        assert!(session.is_closed());
    }

    #[test]
    fn inverse_is_an_involution() {
        let changes = [
            Change::SetAddr {
                old: None,
                new: Some((dns(1), 24)),
            },
            Change::SetMtu {
                old: Some(1500),
                new: Some(1396),
            },
            Change::SetRoutes {
                old: vec![route(1)],
                new: vec![route(2)],
            },
            Change::SetDns {
                old: vec![dns(1)],
                new: vec![dns(2)],
            },
            Change::AddRoute(route(5)),
            Change::RemoveRoute(route(6)),
        ];

        for change in changes {
            assert_eq!(change.inverse().inverse(), change);
        }
    }
}
