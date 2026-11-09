cask "aevan" do
  version "0.2.5"
  sha256 "12c4702234809c33a1942f1ef20c816cd7baecb784d915b8b87057cda46c3cc6"

  url "https://github.com/kilisk/Aevan/releases/download/v#{version}/aevan-#{version}-arm64%2Bx86_64.dmg"
  name "Aevan"
  desc "Independent Ivanti Secure Access (Network Connect) client"
  homepage "https://github.com/kilisk/Aevan"

  depends_on macos: ">= :big_sur"

  app "Aevan.app"

  uninstall quit: "com.github.kilisk.aevan",
            launchctl: "com.github.kilisk.aevand",
            delete: [
              "/Library/LaunchDaemons/com.github.kilisk.aevand.plist",
              "~/Library/Application Support/aevan",
              "~/Library/Caches/com.github.kilisk.aevan",
              "~/Library/Preferences/com.github.kilisk.aevan.plist",
              "~/Library/Saved Application State/com.github.kilisk.aevan.savedState",
            ]

  zap trash: [
        "/Applications/Aevan.app",
      ],
      delete: [
        "/Library/LaunchDaemons/com.github.kilisk.aevand.plist",
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
      banner asks for administrator approval once.

      This cask installs the app only. For aevan and aevand on PATH, install
      the .pkg from the same release.

      Uninstalling the cask removes the profile store too. To keep profiles,
      copy ~/Library/Application Support/aevan first.
    EOS
  end
end
