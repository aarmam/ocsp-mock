package com.nortal.ocsp.mock.controller;

import com.nortal.ocsp.mock.service.OcspResponderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
class OcspResponderController {
    private static final String STATUS_REQUEST_PATH = "/status";
    private static final MediaType OCSP_RESPONSE_MEDIA_TYPE = new MediaType("application", "ocsp-response");
    private final OcspResponderService ocspResponderService;

    @PostMapping(STATUS_REQUEST_PATH)
    ResponseEntity<byte[]> timestamp(@RequestBody byte[] ocspRequest) {

        return ResponseEntity
                .ok()
                .contentType(OCSP_RESPONSE_MEDIA_TYPE)
                .body(ocspResponderService.response(ocspRequest));
    }
}
