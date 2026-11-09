cask "aevan" do
  version "0.2.4"
  sha256 "98d5626570be93ad64d58ae53d4845101581e9e98d2125d24e30849a2ea956f5"

  url "https://github.com/kilisk/Aevan/releases/download/v#{version}/aevan-#{version}-arm64%2Bx86_64.pkg"
  name "Aevan"
  desc "Independent Ivanti Secure Access (Network Connect) client"
  homepage "https://github.com/kilisk/Aevan"

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
