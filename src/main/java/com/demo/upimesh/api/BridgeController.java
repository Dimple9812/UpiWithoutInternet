package com.demo.upimesh.api;

import com.demo.upimesh.protocol.MeshPacket;
import com.demo.upimesh.protocol.SettlementReceipt;
import com.demo.upimesh.service.ApiException;
import com.demo.upimesh.service.IngestionService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * The endpoint a bridge phone calls once it has internet. Final outcomes (SETTLED,
 * REJECTED, DUPLICATE) return 200 with a receipt the bridge gossips back into the mesh;
 * RETRY returns 503 + Retry-After, meaning "keep the packet and try again".
 */
@RestController
@RequestMapping("/api/v1")
public class BridgeController {

    private final IngestionService ingestion;

    public BridgeController(IngestionService ingestion) {
        this.ingestion = ingestion;
    }

    @PostMapping("/bridge/ingest")
    public ResponseEntity<IngestionService.IngestResult> ingest(
            @RequestAttribute(BridgeAuthInterceptor.BRIDGE_ID_ATTR) String bridgeId, // set by the auth interceptor
            @RequestHeader(value = "X-Hop-Count", defaultValue = "0") int hopCount,   // advisory, analytics only
            @Valid @RequestBody MeshPacket packet) {

        IngestionService.IngestResult r = ingestion.ingest(packet, bridgeId, hopCount);
        if (r.outcome() == IngestionService.Outcome.RETRY) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).header(HttpHeaders.RETRY_AFTER, "5").body(r);
        }
        return ResponseEntity.ok(r);
    }

    /** Lets a receiver (or bridge) that comes online later fetch the signed outcome. */
    @GetMapping("/receipts/{packetHash}")
    public SettlementReceipt receipt(@PathVariable String packetHash) {
        if (!packetHash.matches("^[0-9a-f]{64}$")) throw ApiException.badRequest("bad_packet_hash", "expected sha-256 hex");
        return ingestion.receipt(packetHash)
                .orElseThrow(() -> ApiException.notFound("no_receipt", "no settled or rejected payment for this packet"));
    }
}
