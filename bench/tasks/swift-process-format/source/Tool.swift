import Foundation

func runConvertVulnerable(_ tool: String) -> Int32 {
    return system(tool)
}

func runConvertSafe() -> Int32 {
    return system("/usr/bin/convert /tmp/in.png /tmp/out.png")
}
