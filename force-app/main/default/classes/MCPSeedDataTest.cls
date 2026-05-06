/**
 * MCPSeedDataTest — coverage for MCPSeedData.
 *
 * CMT records (MCP_Attack_Payload__mdt) are always visible in test context
 * regardless of SeeAllData — no test setup needed for that dependency.
 * All other data is isolated per test method.
 */
@isTest
private class MCPSeedDataTest {

    // ============================================================================
    // SEED: record counts
    // ============================================================================

    @isTest
    static void testSeedAll_recordCounts() {
        Test.startTest();
        new MCPSeedData().seedAll();
        Test.stopTest();

        System.assertEquals(60, [SELECT COUNT() FROM Account         WHERE Test_Payload_Type__c != null], 'Expected 60 Accounts');
        System.assertEquals(60, [SELECT COUNT() FROM Contact         WHERE Test_Payload_Type__c != null], 'Expected 60 Contacts');
        System.assertEquals(70, [SELECT COUNT() FROM Case            WHERE Test_Payload_Type__c != null], 'Expected 70 Cases');
        System.assertEquals(80, [SELECT COUNT() FROM Outreach_Log__c WHERE Test_Payload_Type__c != null], 'Expected 80 Outreach Logs');
    }

    // ============================================================================
    // SEED: adversarial / benign mix
    // ============================================================================

    @isTest
    static void testSeedAll_adversarialMix() {
        Test.startTest();
        new MCPSeedData().seedAll();
        Test.stopTest();

        // Accounts: 36 benign, 24 adversarial
        System.assertEquals(36, [SELECT COUNT() FROM Account WHERE Is_Adversarial__c = false AND Test_Payload_Type__c != null], 'Expected 36 benign Accounts');
        System.assertEquals(24, [SELECT COUNT() FROM Account WHERE Is_Adversarial__c = true],  'Expected 24 adversarial Accounts');

        // Contacts: 36 benign, 24 adversarial
        System.assertEquals(36, [SELECT COUNT() FROM Contact WHERE Is_Adversarial__c = false AND Test_Payload_Type__c != null], 'Expected 36 benign Contacts');
        System.assertEquals(24, [SELECT COUNT() FROM Contact WHERE Is_Adversarial__c = true],  'Expected 24 adversarial Contacts');

        // Cases: 30 benign, 40 adversarial
        System.assertEquals(30, [SELECT COUNT() FROM Case WHERE Is_Adversarial__c = false AND Test_Payload_Type__c != null], 'Expected 30 benign Cases');
        System.assertEquals(40, [SELECT COUNT() FROM Case WHERE Is_Adversarial__c = true],  'Expected 40 adversarial Cases');

        // Outreach Logs: 32 benign, 48 adversarial
        System.assertEquals(32, [SELECT COUNT() FROM Outreach_Log__c WHERE Is_Adversarial__c = false AND Test_Payload_Type__c != null], 'Expected 32 benign Outreach Logs');
        System.assertEquals(48, [SELECT COUNT() FROM Outreach_Log__c WHERE Is_Adversarial__c = true],  'Expected 48 adversarial Outreach Logs');
    }

    // ============================================================================
    // SEED: honeytoken format
    // ============================================================================

    @isTest
    static void testSeedAll_honeytokenFormat() {
        Test.startTest();
        new MCPSeedData().seedAll();
        Test.stopTest();

        // HONEYTOKEN-{6}-{3} = 21 chars, prefix always HONEYTOKEN-
        for (Account a : [SELECT Honeytoken_Id__c FROM Account WHERE Honeytoken_Id__c != null]) {
            System.assert(a.Honeytoken_Id__c.startsWith('HONEYTOKEN-'), 'Bad prefix on Account honeytoken: ' + a.Honeytoken_Id__c);
            System.assertEquals(21, a.Honeytoken_Id__c.length(), 'Wrong length on Account honeytoken: ' + a.Honeytoken_Id__c);
        }

        for (Contact c : [SELECT Honeytoken_Id__c FROM Contact WHERE Honeytoken_Id__c != null]) {
            System.assert(c.Honeytoken_Id__c.startsWith('HONEYTOKEN-'), 'Bad prefix on Contact honeytoken: ' + c.Honeytoken_Id__c);
            System.assertEquals(21, c.Honeytoken_Id__c.length(), 'Wrong length on Contact honeytoken: ' + c.Honeytoken_Id__c);
        }

        for (Case cs : [SELECT Honeytoken_Id__c FROM Case WHERE Honeytoken_Id__c != null]) {
            System.assert(cs.Honeytoken_Id__c.startsWith('HONEYTOKEN-'), 'Bad prefix on Case honeytoken: ' + cs.Honeytoken_Id__c);
            System.assertEquals(21, cs.Honeytoken_Id__c.length(), 'Wrong length on Case honeytoken: ' + cs.Honeytoken_Id__c);
        }
    }

    // ============================================================================
    // SEED: honeytokens are unique within a run
    // ============================================================================

    @isTest
    static void testSeedAll_honeytokenUniqueness() {
        Test.startTest();
        new MCPSeedData().seedAll();
        Test.stopTest();

        Set<String> seen = new Set<String>();

        for (Account a     : [SELECT Honeytoken_Id__c FROM Account         WHERE Honeytoken_Id__c != null]) {
            System.assert(seen.add(a.Honeytoken_Id__c), 'Duplicate honeytoken on Account: '      + a.Honeytoken_Id__c);
        }
        for (Contact c     : [SELECT Honeytoken_Id__c FROM Contact         WHERE Honeytoken_Id__c != null]) {
            System.assert(seen.add(c.Honeytoken_Id__c), 'Duplicate honeytoken on Contact: '      + c.Honeytoken_Id__c);
        }
        for (Case cs       : [SELECT Honeytoken_Id__c FROM Case            WHERE Honeytoken_Id__c != null]) {
            System.assert(seen.add(cs.Honeytoken_Id__c), 'Duplicate honeytoken on Case: '        + cs.Honeytoken_Id__c);
        }
        for (Outreach_Log__c ol : [SELECT Honeytoken_Id__c FROM Outreach_Log__c WHERE Honeytoken_Id__c != null]) {
            System.assert(seen.add(ol.Honeytoken_Id__c), 'Duplicate honeytoken on Outreach Log: ' + ol.Honeytoken_Id__c);
        }
    }

    // ============================================================================
    // SEED: sensitivity labels populated
    // ============================================================================

    @isTest
    static void testSeedAll_sensitivityLabels() {
        Test.startTest();
        new MCPSeedData().seedAll();
        Test.stopTest();

        // Every adversarial record should have a Sensitivity_Label__c set
        System.assertEquals(
            0,
            [SELECT COUNT() FROM Account WHERE Is_Adversarial__c = true AND Sensitivity_Label__c = null],
            'Adversarial Accounts should all have a Sensitivity_Label__c'
        );
        System.assertEquals(
            0,
            [SELECT COUNT() FROM Outreach_Log__c WHERE Is_Adversarial__c = true AND Sensitivity_Label__c = null],
            'Adversarial Outreach Logs should all have a Sensitivity_Label__c'
        );

        // Restricted-label records exist (cross-tenant, auth-test payloads)
        System.assert(
            [SELECT COUNT() FROM Account WHERE Sensitivity_Label__c = 'Restricted'] > 0,
            'Expected at least one Restricted Account'
        );
    }

    // ============================================================================
    // CLEANUP
    // ============================================================================

    @isTest
    static void testCleanupAll() {
        new MCPSeedData().seedAll();

        Test.startTest();
        new MCPSeedData().cleanupAll();
        Test.stopTest();

        System.assertEquals(0, [SELECT COUNT() FROM Outreach_Log__c WHERE Test_Payload_Type__c != null], 'Outreach Logs not cleaned up');
        System.assertEquals(0, [SELECT COUNT() FROM Case            WHERE Test_Payload_Type__c != null], 'Cases not cleaned up');
        System.assertEquals(0, [SELECT COUNT() FROM Contact         WHERE Test_Payload_Type__c != null], 'Contacts not cleaned up');
        System.assertEquals(0, [SELECT COUNT() FROM Account         WHERE Test_Payload_Type__c != null], 'Accounts not cleaned up');
    }

    // ============================================================================
    // EXCEPTION class is usable
    // ============================================================================

   @isTest
static void testMCPSeedException() {
    String msg = 'No active MCP_Attack_Payload__mdt records found for type: Fake_Type';
    try {
        throw new MCPSeedData.MCPSeedException(msg);
    } catch (MCPSeedData.MCPSeedException e) {
        System.assertEquals(msg, e.getMessage());
    }
}
}