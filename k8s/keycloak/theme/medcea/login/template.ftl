<#-- MedCEA login layout. Every login-type page (sign in, forgot password,
     update password, errors, logout confirmation) renders inside this macro,
     so they all share the portal's look. The section contract is base's:
     "header", "form", "info", "socialProviders", "show-username". -->
<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>${msg("loginTitle",(realm.displayName!''))}</title>
    <#if properties.styles?has_content>
        <#list properties.styles?split(' ') as style>
            <link href="${url.resourcesPath}/${style}" rel="stylesheet" />
        </#list>
    </#if>
    <#if scripts??>
        <#list scripts as script>
            <script src="${script}" type="text/javascript"></script>
        </#list>
    </#if>
    <script type="module">
        import { startSessionPolling } from "${url.resourcesPath}/js/authChecker.js";
        startSessionPolling("${url.ssoLoginInOtherTabsUrl?no_esc}");
    </script>
</head>
<body class="${bodyClass}">
<div class="bg" style="background-image:url('${url.resourcesPath}/img/bg.jpg')"></div>
<main class="shell">
    <div class="brand">
        <svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M2 21h20" stroke="#cbd5e1" stroke-width="1.5"/><path d="M4 21V8l4 3V8l4 3v9" stroke="#cbd5e1" stroke-width="1.5"/>
            <path d="M6 18h2M10 18h2" stroke="#cbd5e1" stroke-width="1.5"/>
            <path d="M18.5 21v-4" stroke="#fbbf24" stroke-width="2"/>
            <path d="M15.5 17c0-3 6-3 6 0H15.5z" stroke="#fbbf24" stroke-width="1.5" fill="#fbbf24" fill-opacity=".2"/>
            <path d="M14 21v-6c0-1.5-1-2.5-2.5-2.5" stroke="#4ade80" stroke-width="1.5"/>
            <path d="M11.5 12.5c-1.5-1.5-3.5-.5-3.5 1.5s2 1.5 3.5.5Z" stroke="#4ade80" stroke-width="1.5" fill="#4ade80" fill-opacity=".2"/>
            <path d="M11.5 12.5c0-1.5 1.5-2.5 2.5-1.5" stroke="#4ade80" stroke-width="1.5"/>
        </svg>
        <div>
            <div class="brand-name">MedCEA Platform</div>
            <div class="brand-sub">Medical Controlled Environment Agriculture</div>
        </div>
    </div>

    <section class="card">
        <header class="card-head">
            <#if !(auth?has_content && auth.showUsername() && !auth.showResetCredentials())>
                <div id="kc-page-title" class="title"><#nested "header"></div>
            <#else>
                <#nested "show-username">
                <div class="attempted">
                    <span>${auth.attemptedUsername}</span>
                    <a href="${url.loginRestartFlowUrl}" title="${msg("restartLoginTooltip")}">${msg("restartLoginTooltip")}</a>
                </div>
            </#if>
        </header>

        <#-- App-initiated actions should not see warnings about completing the action. -->
        <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
            <div class="alert alert-${message.type}" role="alert">
                <span class="alert-text">${kcSanitize(message.summary)?no_esc}</span>
            </div>
        </#if>

        <#nested "form">

        <#if auth?has_content && auth.showTryAnotherWayLink()>
            <form id="kc-select-try-another-way-form" action="${url.loginAction}" method="post">
                <input type="hidden" name="tryAnotherWay" value="on"/>
                <a href="#" class="link" onclick="document.forms['kc-select-try-another-way-form'].requestSubmit();return false;">${msg("doTryAnotherWay")}</a>
            </form>
        </#if>

        <#nested "socialProviders">

        <#if displayInfo>
            <div class="info"><#nested "info"></div>
        </#if>
    </section>

    <footer class="foot">MedCEA &mdash; ISCTE-IUL &middot; IT-IUL</footer>
</main>
</body>
</html>
</#macro>
