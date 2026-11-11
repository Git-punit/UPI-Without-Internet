plugins {
    id("com.android.application")
}

android {
    namespace = "com.upioffline.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.upioffline.app"
        minSdk = 26 // java.util.Base64 used by the shared protocol code
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // Compile the shared protocol module's sources straight in, so phone and backend use the same code.
    sourceSets["main"].java.srcDir("../../protocol/src/main/java")
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517") // real org.json for JVM unit tests (Android's is a stub there)
}
