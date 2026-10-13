package com.demo.upimesh.demo.mesh;

/**
 * Knobs for the mesh simulation. Distances are in arbitrary map units; time is in ticks.
 *
 * @param coverageX         nodes with x >= coverageX have 4G (the "edge of the basement")
 * @param radioRange        two phones closer than this can exchange data
 * @param bufferCapacity    max packets a phone will carry for strangers + itself
 * @param initialCopies     spray-and-wait L: copies a sender sprays before waiting
 * @param packetLifetime    ticks after which a relay drops a packet it is carrying
 * @param maxPerContact     packets moved per direction per contact (radio time is limited)
 */
public record MeshConfig(
        double width,
        double height,
        double coverageX,
        double radioRange,
        double minSpeed,
        double maxSpeed,
        int bufferCapacity,
        int initialCopies,
        int packetLifetime,
        int maxPerContact,
        int receiptCapacity,
        double idleDrain,
        double scanDrain,
        double chargeRate,
        double lowBattery,
        double criticalBattery) {

    public static MeshConfig defaults() {
        return new MeshConfig(100, 60, 84, 17, 0.6, 2.2,
                12, 8, 300, 4, 256,
                0.03, 0.12, 0.8, 20, 4);
    }
}
