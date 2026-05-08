/**
 * MCPSeedDataTest — coverage for MCPSeedData.
 *
 * CMT records (MCP_Attack_Payload__mdt) are always visible in test context
 * regardless of SeeAllData — no test setup needed for that dependency.
 * All other data is isolated per test method.
 *
 * Record counts and adversarial/benign splits are verified via
 * MCP_Test_Manifest__c rather than per-object field filters, since
 * Test_Payload_Type__c / Is_Adversarial__c / Honeytoken_Id__c now live
 * on the manifest object instead of the target objects.
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

        System.assertEquals(60, [SELECT COUNT() FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Account'],        'Expected 60 Account manifest rows');
        System.assertEquals(60, [SELECT COUNT() FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Contact'],        'Expected 60 Contact manifest rows');
        System.assertEquals(70, [SELECT COUNT() FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Case'],           'Expected 70 Case manifest rows');
        System.assertEquals(80, [SELECT COUNT() FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Outreach_Log__c'],'Expected 80 Outreach Log manifest rows');
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
        System.assertEquals(36, [SELECT COUNT() FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Account' AND Payload_Type__c =  'Benign'], 'Expected 36 benign Account rows');
        System.assertEquals(24, [SELECT COUNT() FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Account' AND Payload_Type__c != 'Benign'], 'Expected 24 adversarial Account rows');

        // Contacts: 36 benign, 24 adversarial
        System.assertEquals(36, [SELECT COUNT() FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Contact' AND Payload_Type__c =  'Benign'], 'Expected 36 benign Contact rows');
        System.assertEquals(24, [SELECT COUNT() FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Contact' AND Payload_Type__c != 'Benign'], 'Expected 24 adversarial Contact rows');

        // Cases: 30 benign, 40 adversarial
        System.assertEquals(30, [SELECT COUNT() FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Case' AND Payload_Type__c =  'Benign'], 'Expected 30 benign Case rows');
        System.assertEquals(40, [SELECT COUNT() FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Case' AND Payload_Type__c != 'Benign'], 'Expected 40 adversarial Case rows');

        // Outreach Logs: 32 benign, 48 adversarial
        System.assertEquals(32, [SELECT COUNT() FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Outreach_Log__c' AND Payload_Type__c =  'Benign'], 'Expected 32 benign Outreach Log rows');
        System.assertEquals(48, [SELECT COUNT() FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Outreach_Log__c' AND Payload_Type__c != 'Benign'], 'Expected 48 adversarial Outreach Log rows');
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
        for (MCP_Test_Manifest__c m : [SELECT Honeytoken_Value__c, Target_Object_Type__c FROM MCP_Test_Manifest__c WHERE Honeytoken_Value__c != null]) {
            System.assert(m.Honeytoken_Value__c.startsWith('HONEYTOKEN-'), 'Bad prefix on ' + m.Target_Object_Type__c + ' honeytoken: ' + m.Honeytoken_Value__c);
            System.assertEquals(21, m.Honeytoken_Value__c.length(), 'Wrong length on ' + m.Target_Object_Type__c + ' honeytoken: ' + m.Honeytoken_Value__c);
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
        for (MCP_Test_Manifest__c m : [SELECT Honeytoken_Value__c FROM MCP_Test_Manifest__c WHERE Honeytoken_Value__c != null]) {
            System.assert(seen.add(m.Honeytoken_Value__c), 'Duplicate honeytoken across manifest: ' + m.Honeytoken_Value__c);
        }
    }

    // ============================================================================
    // SEED: sensitivity labels populated on adversarial target records
    // ============================================================================

    @isTest
    static void testSeedAll_sensitivityLabels() {
        Test.startTest();
        new MCPSeedData().seedAll();
        Test.stopTest();

        // Collect adversarial Account IDs from the manifest, then verify Sensitivity_Label__c is set
        Set<Id> adversarialAccountIds = new Set<Id>();
        for (MCP_Test_Manifest__c m : [SELECT Target_Record_Id__c FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Account' AND Payload_Type__c != 'Benign']) {
            adversarialAccountIds.add((Id) m.Target_Record_Id__c);
        }
        System.assertEquals(
            0,
            [SELECT COUNT() FROM Account WHERE Id IN :adversarialAccountIds AND Sensitivity_Label__c = null],
            'Adversarial Accounts should all have a Sensitivity_Label__c'
        );

        Set<Id> adversarialLogIds = new Set<Id>();
        for (MCP_Test_Manifest__c m : [SELECT Target_Record_Id__c FROM MCP_Test_Manifest__c WHERE Target_Object_Type__c = 'Outreach_Log__c' AND Payload_Type__c != 'Benign']) {
            adversarialLogIds.add((Id) m.Target_Record_Id__c);
        }
        System.assertEquals(
            0,
            [SELECT COUNT() FROM Outreach_Log__c WHERE Id IN :adversarialLogIds AND Sensitivity_Label__c = null],
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

        System.assertEquals(0, [SELECT COUNT() FROM MCP_Test_Manifest__c], 'Manifest not cleaned up');
        System.assertEquals(0, [SELECT COUNT() FROM Outreach_Log__c],      'Outreach Logs not cleaned up');
        System.assertEquals(0, [SELECT COUNT() FROM Case],                 'Cases not cleaned up');
        System.assertEquals(0, [SELECT COUNT() FROM Contact],              'Contacts not cleaned up');
        System.assertEquals(0, [SELECT COUNT() FROM Account],              'Accounts not cleaned up');
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
