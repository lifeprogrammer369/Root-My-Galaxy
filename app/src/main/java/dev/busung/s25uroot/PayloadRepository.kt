package dev.busung.s25uroot

import android.content.Context
import android.system.Os
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
)

class PayloadRepository(private val context: Context) {
    fun loadTargets(): List<TargetProfile> {
        var lastError: Throwable? = null
        for (repository in repositoryCandidates()) {
            val rawRepository = "https://raw.githubusercontent.com/$repository"
            val mutablePrefix = "$rawRepository/main/"
            try {
                val commit = resolveMainCommit(repository)
                val manifestBytes = downloadBytes(
                    "$rawRepository/$commit/support/targets-v3.json",
                    MAX_MANIFEST_BYTES,
                )
                return SupportManifest.parse(manifestBytes).targets.map { profile ->
                    profile.copy(
                        exploit = profile.exploit.copy(
                            url = pinArtifactUrl(profile.exploit.url, commit, mutablePrefix, rawRepository),
                        ),
                        kernelSu = profile.kernelSu.copy(
                            url = pinArtifactUrl(profile.kernelSu.url, commit, mutablePrefix, rawRepository),
                        ),
                    )
                }
            } catch (error: Throwable) {
                lastError = error
                if (!shouldFallbackToMain(error)) {
                    continue
                }
            }
            try {
                val manifestBytes = downloadBytes(
                    "${mutablePrefix}support/targets-v3.json",
                    MAX_MANIFEST_BYTES,
                )
                return SupportManifest.parse(manifestBytes).targets.map { profile ->
                    profile.copy(
                        exploit = profile.exploit.copy(
                            url = normalizeToMutableRaw(profile.exploit.url, mutablePrefix),
                        ),
                        kernelSu = profile.kernelSu.copy(
                            url = normalizeToMutableRaw(profile.kernelSu.url, mutablePrefix),
                        ),
                    )
                }
            } catch (error: Throwable) {
                lastError = error
            }
        }
        throw (lastError ?: IllegalStateException(context.getString(R.string.repo_no_profile)))
    }

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile = loadTargets()
        .firstOrNull { it.matches(snapshot) }
        ?: error(context.getString(R.string.repo_no_profile))

    fun resolveTarget(profileId: String): TargetProfile = loadTargets()
        .firstOrNull { it.profileId == profileId }
        ?: error(context.getString(R.string.repo_profile_missing, profileId))

    fun download(profile: TargetProfile, onProgress: (String) -> Unit): VerifiedPayloads {
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
        val exploit = downloadArtifact(
            profile.exploit,
            File(directory, "cve-2026-43499-app.so"),
            context.getString(R.string.artifact_exploit),
            onProgress,
        )
        val kernelSu = downloadArtifact(
            profile.kernelSu,
            File(directory, "ksud-s25u-kdp"),
            context.getString(R.string.artifact_kernelsu),
            onProgress,
        )
        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        return VerifiedPayloads(profile, exploit, kernelSu)
    }

    private fun downloadArtifact(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        onProgress(context.getString(R.string.repo_downloading, label))
        val temporary = File(destination.parentFile, "${destination.name}.part")
        val openResult = openFirstOk(candidateArtifactUrls(artifact.url))
        val connection = openResult.connection
        onProgress("[*] URL: ${openResult.url}")
        require(connection.contentLengthLong == -1L || connection.contentLengthLong == artifact.size) {
            context.getString(R.string.repo_size_mismatch, label)
        }
        var total = 0L
        connection.inputStream.use { input ->
            FileOutputStream(temporary).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= artifact.size) {
                        context.getString(R.string.repo_size_exceeded, label)
                    }
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
            }
        }
        connection.disconnect()
        require(total == artifact.size) { context.getString(R.string.repo_incomplete, label) }
        if (destination.exists()) destination.delete()
        require(temporary.renameTo(destination)) {
            context.getString(R.string.repo_finalize_failed, label)
        }
        onProgress(context.getString(R.string.repo_verified, label))
        return destination
    }

    private fun resolveMainCommit(repository: String): String {
        val response = downloadBytes(
            "https://api.github.com/repos/$repository/git/ref/heads/main",
            MAX_COMMIT_RESPONSE_BYTES,
        )
        val commit = JSONObject(response.toString(Charsets.UTF_8))
            .getJSONObject("object")
            .getString("sha")
        require(commit.matches(Regex("[0-9a-f]{40}"))) { context.getString(R.string.repo_commit_invalid) }
        return commit
    }

    private fun shouldFallbackToMain(error: Throwable): Boolean {
        val message = error.message ?: return false
        if (!message.startsWith("HTTP ")) {
            return true
        }
        val code = message.removePrefix("HTTP ").trim().toIntOrNull() ?: return true
        return code >= 400
    }

    private fun normalizeToMutableRaw(url: String, mutablePrefix: String): String {
        val mainMarker = "/main/"
        val mainIndex = url.indexOf(mainMarker)
        require(mainIndex >= 0) { context.getString(R.string.repo_url_invalid) }
        val suffix = url.substring(mainIndex + mainMarker.length)
        return "$mutablePrefix$suffix"
    }

    private fun pinArtifactUrl(
        url: String,
        commit: String,
        mutablePrefix: String,
        rawRepository: String,
    ): String {
        require(url.startsWith(mutablePrefix)) { context.getString(R.string.repo_url_invalid) }
        return "$rawRepository/$commit/${url.removePrefix(mutablePrefix)}"
    }

    private fun downloadBytes(url: String, maximum: Int): ByteArray {
        val connection = open(url)
        val bytes = connection.inputStream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) {
                    context.getString(R.string.repo_response_too_large)
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        connection.disconnect()
        return bytes
    }

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "S25URoot/${BuildConfig.VERSION_NAME}")
            connect()
            require(responseCode == HttpURLConnection.HTTP_OK) { "HTTP $responseCode" }
        }

    private fun openFirstOk(urls: List<String>): OpenResult {
        var lastError: Throwable? = null
        for (url in urls) {
            try {
                return OpenResult(open(url), url)
            } catch (error: Throwable) {
                lastError = error
            }
        }
        throw (lastError ?: IllegalStateException("no candidate URL"))
    }

    private fun repositoryCandidates(): List<String> = listOf(
        PAYLOADS_REPOSITORY,
        "lifeprogrammer369/Root-My-Galaxy-Payloads",
        "lifeprogrammer269/Root-My-Galaxy-Payloads",
    ).distinct()

    private fun candidateArtifactUrls(url: String): List<String> {
        val regex = Regex("^https://raw\\.githubusercontent\\.com/([^/]+)/Root-My-Galaxy-Payloads/(.+)$")
        val match = regex.find(url) ?: return listOf(url)
        val suffix = match.groupValues[2]
        val users = listOf("lifeprogrammer369", "lifeprogrammer269")
        val out = LinkedHashSet<String>()

        for (user in users) {
            out += "https://raw.githubusercontent.com/$user/Root-My-Galaxy-Payloads/$suffix"
        }

        val split = suffix.split('/', limit = 2)
        if (split.size == 2 && split[0].matches(Regex("[0-9a-f]{40}"))) {
            val path = split[1]
            for (user in users) {
                out += "https://raw.githubusercontent.com/$user/Root-My-Galaxy-Payloads/main/$path"
            }
        }

        return out.toList()
    }

    private data class OpenResult(
        val connection: HttpURLConnection,
        val url: String,
    )

    companion object {
        private const val PAYLOADS_REPOSITORY = BuildConfig.PAYLOADS_REPO
        private const val MAX_COMMIT_RESPONSE_BYTES = 16 * 1024
        private const val MAX_MANIFEST_BYTES = 256 * 1024
    }
}
