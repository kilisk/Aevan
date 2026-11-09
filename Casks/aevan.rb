cask "aevan" do
  version "0.2.2"
  sha256 "b46f885e33efe0c93c436d92ff1344025667b5ffaa65732a4afcafb5df9054b3"

  url "https://github.com/kilisk/aevan/releases/download/v#{version}/aevan-#{version}-arm64%2Bx86_64.pkg"
  name "Aevan"
  desc "Independent Ivanti Secure Access (Network Connect) client"
  homepage "https://github.com/kilisk/aevan"

  depends_on macos: ">= :big_sur"

  pkg "aevan-#{version}-arm64+x86_64.pkg"

  uninstall pkgutil: "com.github.kilisk.aevan",
            launchctl: "com.github.kilisk.aevand"

  caveats do
    <<~EOS
      The package is unsigned and not notarised. Gatekeeper will warn on first
      launch; open /Applications/Aevan.app with Control-click -> Open.

      The LaunchDaemon is installed but not loaded. To run the daemon at boot:
        sudo launchctl bootstrap system /Library/LaunchDaemons/com.github.kilisk.aevand.plist
        sudo launchctl enable system/com.github.kilisk.aevand

      Uninstalling the cask keeps the profile store. To remove profiles too,
      run this before uninstalling:
        sudo /usr/local/bin/aevan-uninstall --purge
    EOS
  end
end
