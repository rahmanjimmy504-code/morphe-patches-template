group = "app.worldboxresearch"

patches {
    about {
        name = "WorldBox 0.51.4 Patch Research"
        description = "Research toward a WorldBox 0.51.4 Premium patch; no patch available yet"
        source = "https://github.com/rahmanjimmy504-code/morphe-patches-template"
        author = "rahmanjimmy504-code"
        contact = "https://github.com/rahmanjimmy504-code/morphe-patches-template/issues"
        website = "https://github.com/rahmanjimmy504-code/morphe-patches-template"
        license = "GPLv3"
    }
}

// Separate configuration so gson is available at runtime for the
// generatePatchesList task but never bundled into the APK.
val patchListGeneratorClasspath = configurations.create("patchListGeneratorClasspath")

dependencies {
    compileOnly(libs.gson)
    patchListGeneratorClasspath(libs.gson)
}

tasks {
    register<JavaExec>("generatePatchesList") {
        description = "Build patch with patch list"

        dependsOn(build)

        classpath = sourceSets["main"].runtimeClasspath + patchListGeneratorClasspath
        mainClass.set("util.PatchListGeneratorKt")
    }

    // Used by gradle-semantic-release-plugin.
    publish {
        dependsOn("generatePatchesList")
    }
}
