import RemozioCore

@main
struct FrontendMain {
    static func main() {
        #if DEBUG
        let domain = "dev.sebastiano.remozio.macos.debug"
        #else
        let domain = "dev.sebastiano.remozio.macos"
        #endif
        CommandFrontendMain.run(count: CommandLine.argc, vector: CommandLine.unsafeArgv, preferencesDomain: domain).finish()
    }
}
