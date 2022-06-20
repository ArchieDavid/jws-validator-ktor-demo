package com.example.plugins

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.RSASSASigner
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
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

fun Application.configureRouting() {

    val RSA_PUBLIC_KEY_STR = """-----BEGIN PUBLIC KEY-----
    removed!
    -----END PUBLIC KEY-----""".trimIndent()

    val RSA_PRIVATE_KEY_STR = """-----BEGIN PRIVATE KEY-----
    removed!
    -----END PRIVATE KEY-----""".trimIndent()

    val keyFactory = KeyFactory.getInstance("RSA")

    val RSA_PUBLIC_KEY = keyFactory.generatePublic(
        X509EncodedKeySpec(
            Base64.getDecoder().decode(
                removeEncapsulationBoundaries(RSA_PUBLIC_KEY_STR)
            )
        )
    ) as RSAPublicKey


    val RSA_PRIVATE_KEY = keyFactory.generatePrivate(
        PKCS8EncodedKeySpec(
            Base64.getDecoder().decode(
                removeEncapsulationBoundaries(RSA_PRIVATE_KEY_STR)
            )
        )
    ) as RSAPrivateKey


    routing {
        post("/validatesignature") {
            val person = call.receive<Person>()
            val xJwsSignature = call.request.header("x-jws-signature")

            println("jsonPayloadStr : " + person)
            println("xJwsSignature : " + xJwsSignature)

            val personJson = ObjectMapper().writeValueAsString(person)
            println("personJson = $personJson")

            val payload = Payload(personJson)

            val jwsObject = JWSObject.parse(xJwsSignature, payload)
            println("JWEOBJECT: " + jwsObject.toString())
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


        post("/sign") {
            try {
                val person = call.receive<Person>()
                println("person = $person")

                val personJson = ObjectMapper().writeValueAsString(person)
                println("personJson = $personJson")

                val payload = Payload(personJson)
                val jwsObject = JWSObject(
                    JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                    payload
                )

                val signer: JWSSigner = RSASSASigner(RSA_PRIVATE_KEY)

                jwsObject.sign(signer)
                val isDetached = true
                val signature = jwsObject.serialize(isDetached)

                println("signature = " + signature)
                call.respond(HttpStatusCode.OK, "created signature =  $signature")
            } catch (t: Throwable) {
                println(t)
                call.respond(HttpStatusCode.InternalServerError)
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


data class Person(val name: String, val age: Int)