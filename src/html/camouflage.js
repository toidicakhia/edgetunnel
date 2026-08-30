/**
 * src/html/camouflage.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */

export async function nginx() {
	return `
	<!DOCTYPEHtml>
	<html>
	<head>
	<title>WelcomeToNginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0Auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>WelcomeToNginx!</h1>
	<p>If youSee this page, theNginxWebServerIsSuccessfullyInstalledAnd
	working. FurtherConfigurationIsRequired.</p>

	<p>For onlineDocumentationAndSupportPleaseReferTo
	<aHref="http://nginx.org/">nginx.org</a>.<br/>
	CommercialSupportIsAvailableAt
	<aHref="http://nginx.com/">nginx.com</a>.</p>

	<p><em>ThankYou for usingNginx.</em></p>
	</body>
	</html>
	`
}


export async function html1101(host, accessIP) {
	const now = new Date();
	const formattedTimestamp = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') + ' ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
	const randomstr = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');

	return `<!DOCTYPE html>
<!--[if ltIE7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gtIE8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>WorkerThrewException | ${host} | Cloudflare</title>
<metaCharset="UTF-8" />
<metaHttp-equiv="Content-Type" content="text/html; charset=UTF-8" />
<metaHttp-equiv="X-UA-Compatible" content="IE=Edge" />
<metaName="robots" content="noindex, nofollow" />
<metaName="viewport" content="width=device-width,initial-scale=1" />
<linkRel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if ltIE9]><linkRel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>


<!--[if gteIE10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->

</head>
<body>
    <divId="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">PleaseEnableCookies.</div>
        <divId="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    <small class="heading-ray-id">RayID: ${randomstr} &bull; ${formattedTimestamp} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">WorkerThrewException</h2>
            </div><!-- /.header -->

            <section></section><!-- spacer -->

            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2Data-translate="what_happened">WhatHappened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>

                    <div class="cf-column">
                        <h2Data-translate="what_can_i_do">WhatCanI do?</h2>
                            <p><strong>If youAreTheOwner of this website:</strong><br />referTo <aHref="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - ErrorsAndExceptions</a> andCheckWorkersLogs for ${host}.</p>
                    </div>

                </div>
            </div><!-- /.section -->

            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      <span class="cf-footer-item sm:block sm:mb-1">CloudflareRayID: <strong class="font-semibold"> ${randomstr}</strong></span>
      <span class="cf-footer-separator sm:hidden">&bull;</span>
      <spanId="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        YourIP:
        <buttonType="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">ClickToReveal</button>
        <span class="hidden" id="cf-footer-ip">${accessIP}</span>
        <span class="cf-footer-separator sm:hidden">&bull;</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; securityBy</span> <aRel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>

    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};


  </script>
</body>
</html>`;
}