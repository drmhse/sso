import { SsoClient, SsoApiError } from '@drmhse/sso-sdk';

const API_URL = 'http://localhost:3000';
// These values match the test service in your database
const ORG_SLUG = 'amp-dev';
const SERVICE_SLUG = 'sdd';
const CLIENT_ID = 'e196621f-0c59-4524-a52b-adc9edfe0e8a';

const sso = new SsoClient({ baseURL: API_URL });

async function main() {
  console.log(`\n🚀 Starting CLI Authentication for ${ORG_SLUG}/${SERVICE_SLUG}...\n`);

  try {
    // Step 1: Request device and user codes for a specific organization and service
    console.log('Requesting device code from SSO platform...');
    const deviceAuth = await sso.auth.deviceCode.request({
      client_id: CLIENT_ID,
      org: ORG_SLUG,
      service: SERVICE_SLUG,
    });

    console.log('\n✅ Device code received!\n');
    console.log('═'.repeat(60));
    console.log('📱 To authorize this CLI:');
    console.log('═'.repeat(60));
    console.log(`\n1️⃣  Open this URL in your browser:`);
    console.log(`   ${deviceAuth.verification_uri}\n`);
    console.log(`2️⃣  Enter this code:`);
    console.log(`   \x1b[36m\x1b[1m${deviceAuth.user_code}\x1b[0m\n`);
    console.log('═'.repeat(60));
    console.log('\n⏳ Waiting for authorization...\n');

    // Step 2: Poll for the token
    await pollForToken(deviceAuth);

  } catch (error) {
    console.error(`\n❌ Authentication failed: ${error.message}`);
    if (error instanceof SsoApiError) {
      console.error(`   Error Code: ${error.errorCode}`);
    }
    process.exit(1);
  }
}

async function pollForToken(deviceAuth) {
  const { device_code, interval } = deviceAuth;
  const startTime = Date.now();
  const expiresIn = deviceAuth.expires_in * 1000;

  while (Date.now() - startTime < expiresIn) {
    await new Promise(resolve => setTimeout(resolve, interval * 1000));

    try {
      const tokenResponse = await sso.auth.deviceCode.exchangeToken({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: device_code,
        client_id: CLIENT_ID,
      });

      console.log('═'.repeat(60));
      console.log('\n✅ \x1b[32m\x1b[1mAuthentication successful!\x1b[0m\n');
      console.log('═'.repeat(60));
      console.log(`\n🎉 You are now authenticated to ${ORG_SLUG}/${SERVICE_SLUG}!`);
      console.log(`\n📄 Access Token: ${tokenResponse.access_token.substring(0, 30)}...`);
      console.log(`   Token Type: ${tokenResponse.token_type}`);
      console.log(`   Expires In: ${tokenResponse.expires_in} seconds\n`);
      console.log('═'.repeat(60));
      console.log('\n💾 In a real application, you would save this token securely');
      console.log('   and use it to access protected resources.\n');

      return;
    } catch (error) {
      if (error instanceof SsoApiError) {
        if (error.errorCode === 'DEVICE_CODE_PENDING') {
          // This is expected, continue polling
          process.stdout.write('.');
        } else {
          throw error;
        }
      } else {
        throw error;
      }
    }
  }

  throw new Error('Authentication timed out. Please try again.');
}

main();
