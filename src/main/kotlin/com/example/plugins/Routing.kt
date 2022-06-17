package com.example.plugins

import com.fasterxml.jackson.databind.JsonNode
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.RSASSAVerifier
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.request.header
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

fun Application.configureRouting() {

    val RSA_PUBLIC_KEY_STR = """-----BEGIN PUBLIC KEY-----
    removed!!
    -----END PUBLIC KEY-----""".trimIndent()

    val keyFactory = KeyFactory.getInstance("RSA")

    val RSA_PUBLIC_KEY = keyFactory.generatePublic(
        X509EncodedKeySpec(
            Base64.getDecoder().decode(
                removeEncapsulationBoundaries(RSA_PUBLIC_KEY_STR)
            )
        )
    ) as RSAPublicKey


    // Starting point for a Ktor app:
    routing {
        post("/validatesignature") {
            val jsonPayloadStr = call.receive<JsonNode>().toString()
            val xJwsSignature = call.request.header("x-jws-signature")

            println("jsonPayloadStr : " + jsonPayloadStr)
            println("xJwsSignature : " + xJwsSignature)

            val jwsObject = JWSObject.parse(xJwsSignature, Payload(jsonPayloadStr))

            val verifier = RSASSAVerifier(RSA_PUBLIC_KEY as RSAPublicKey)

            // when
            val verifyResult = jwsObject.verify(verifier)

            if (verifyResult) {
                println("verifyResult : " + verifyResult)
                call.respond(HttpStatusCode.OK, "valid signature found")
            } else {
                println("verifyResult : " + verifyResult)
                call.respond(HttpStatusCode.Unauthorized)
            }
        }

        get("/test") {
            call.respond(HttpStatusCode.OK, "hello world")
        }
    }
    routing {
    }
}


private fun removeEncapsulationBoundaries(key: String): String {
    return key.replace("\n".toRegex(), "")
        .replace(" ".toRegex(), "")
        .replace("-{5}[a-zA-Z]*-{5}".toRegex(), "");
}