cask "aevan" do
  version "0.2.15"
  sha256 "d2b45fe5e31354c5e7aa55954fdc29109139b07d067eeddd02b1d1fc22e8f4d1"

  url "https://github.com/kilisk/Aevan/releases/download/v#{version}/aevan-#{version}-arm64%2Bx86_64.dmg"
  name "Aevan"
  desc "Independent Ivanti Secure Access (Network Connect) client"
  homepage "https://github.com/kilisk/Aevan"

  depends_on macos: ">= :ventura"

  app "Aevan.app"

  uninstall quit: "com.github.kilisk.aevan",
            delete: [
              "~/Library/Application Support/aevan",
              "~/Library/Caches/com.github.kilisk.aevan",
              "~/Library/Preferences/com.github.kilisk.aevan.plist",
              "~/Library/Saved Application State/com.github.kilisk.aevan.savedState",
            ]

  zap trash: [
        "/Applications/Aevan.app",
      ],
      delete: [
        "~/Library/Application Support/aevan",
        "~/Library/Logs/Aevan",
        "~/Library/Caches/com.github.kilisk.aevan",
        "~/Library/Preferences/com.github.kilisk.aevan.plist",
        "~/Library/Saved Application State/com.github.kilisk.aevan.savedState",
      ]

  caveats do
    <<~EOS
      The DMG is unsigned and not notarised. Gatekeeper will warn on first
      launch; open /Applications/Aevan.app with Control-click -> Open, or run:
        xattr -dr com.apple.quarantine /Applications/Aevan.app

      The app contains the daemon. Starting it from the Daemon unavailable
      banner registers the bundled LaunchDaemon with ServiceManagement; approve
      Aevan in System Settings > Login Items & Extensions when macOS asks.

      This cask installs the app only. For aevan and aevand on PATH, install
      the .pkg from the same release.

      Uninstalling the cask removes the profile store too. To keep profiles,
      copy ~/Library/Application Support/aevan first.
    EOS
  end
end
