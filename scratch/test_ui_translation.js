import router from '../src/router.js';
import { nginx, html1101 } from '../src/html/camouflage.js';
import { loginPage } from '../src/html/login.js';
import { noAdminPage, noKVPage } from '../src/html/errorPages.js';
import { translateHtml } from '../src/html/translate.js';

async function runTests() {
	console.log('=== Test 1: loginPage ===');
	const loginHtml = loginPage();
	console.assert(loginHtml.includes('Admin Login'), 'Login must contain Admin Login');
	console.assert(loginHtml.includes('Sign In'), 'Login must contain Sign In');
	console.assert(!loginHtml.includes('登录'), 'Login must not contain Chinese');
	console.log('Test 1 OK');

	console.log('=== Test 2: errorPages ===');
	const noAdmin = noAdminPage();
	console.assert(noAdmin.includes('Admin Password Not Set'), 'noAdmin contains English text');
	const noKV = noKVPage();
	console.assert(noKV.includes('KV Namespace Not Bound'), 'noKV contains English text');
	console.log('Test 2 OK');

	console.log('=== Test 3: camouflage pages ===');
	const nginxHtml = await nginx();
	console.assert(nginxHtml.includes('Welcome to nginx!'), 'nginx contains standard English');
	const error1101 = await html1101('example.com', '1.1.1.1');
	console.assert(error1101.includes('Worker Threw Exception'), '1101 contains English error');
	console.log('Test 3 OK');

	console.log('=== Test 4: Router /login request ===');
	const mockEnv = {
		ADMIN: 'testpass123',
		UUID: 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d',
		KV: { get: async () => null, put: async () => null },
	};
	const reqLogin = new Request('https://test.workers.dev/login');
	const resLogin = await router.fetch(reqLogin, mockEnv, { waitUntil: () => {} });
	const resLoginText = await resLogin.text();
	console.assert(resLogin.status === 200, 'Status should be 200');
	console.assert(resLoginText.includes('Admin Login'), 'Returns English login page');
	console.log('Test 4 OK');

	console.log('=== Test 5: Router missing ADMIN ===');
	const mockEnvNoAdmin = {};
	const reqNoAdmin = new Request('https://test.workers.dev/');
	const resNoAdmin = await router.fetch(reqNoAdmin, mockEnvNoAdmin, { waitUntil: () => {} });
	const resNoAdminText = await resNoAdmin.text();
	console.assert(resNoAdmin.status === 404, 'Status should be 404');
	console.assert(resNoAdminText.includes('Admin Password Not Set'), 'Returns English noADMIN page');
	console.log('Test 5 OK');

	console.log('=== Test 6: Router missing KV ===');
	const mockEnvNoKV = {
		ADMIN: 'testpass123',
	};
	const reqNoKV = new Request('https://test.workers.dev/');
	const resNoKV = await router.fetch(reqNoKV, mockEnvNoKV, { waitUntil: () => {} });
	const resNoKVText = await resNoKV.text();
	console.assert(resNoKV.status === 404, 'Status should be 404');
	console.assert(resNoKVText.includes('KV Namespace Not Bound'), 'Returns English noKV page');
	console.log('Test 6 OK');

	console.log('\nAll UI & Translation Tests Passed Successfully!');
}

runTests().catch(console.error);
