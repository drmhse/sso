<template>
  <div class="min-h-screen bg-white">
    <!-- Navigation -->
    <nav class="border-b border-gray-200 bg-white sticky top-0 z-50">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between h-16">
          <div class="flex items-center">
            <h1 class="text-xl sm:text-2xl font-bold text-gray-900">SSO</h1>
          </div>
          <div class="flex items-center space-x-2 sm:space-x-4">
            <a
              href="https://github.com/drmhse/sso"
              target="_blank"
              rel="noopener noreferrer"
              class="hidden sm:block text-sm text-gray-600 hover:text-gray-900 transition-colors"
            >
              GitHub
            </a>
            <button
              @click="goToLogin"
              class="hidden sm:block text-sm font-medium text-gray-700 hover:text-gray-900 transition-colors px-3 py-2"
            >
              Sign in
            </button>
            <button
              @click="goToLogin"
              class="inline-flex items-center px-3 sm:px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors"
            >
              Get started
            </button>
          </div>
        </div>
      </div>
    </nav>

    <!-- Hero Section -->
    <section class="relative py-12 sm:py-20 lg:py-32">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center">
          <h1 class="text-3xl sm:text-4xl md:text-5xl lg:text-6xl font-bold text-gray-900 tracking-tight leading-tight">
            Enterprise SSO for
            <span class="text-blue-600 block sm:inline"> $10/month</span>
          </h1>
          <p class="mt-4 sm:mt-6 text-lg sm:text-xl lg:text-2xl text-gray-600 max-w-3xl mx-auto px-4">
            Open-source identity platform that scales to millions of users. Self-hosted, fully featured, capital efficient.
          </p>
          <div class="mt-8 sm:mt-10 flex flex-col sm:flex-row gap-3 sm:gap-4 justify-center items-stretch sm:items-center px-4">
            <button
              @click="goToLogin"
              class="inline-flex items-center justify-center px-6 sm:px-8 py-3 sm:py-4 border border-transparent text-base sm:text-lg font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors shadow-lg"
            >
              Start for free
              <svg class="ml-2 -mr-1 w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6" />
              </svg>
            </button>
            <a
              href="https://github.com/drmhse/sso"
              target="_blank"
              rel="noopener noreferrer"
              class="inline-flex items-center justify-center px-6 sm:px-8 py-3 sm:py-4 border border-gray-300 text-base sm:text-lg font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors"
            >
              <svg class="mr-2 w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                <path fill-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.203 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.942.359.31.678.921.678 1.856 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clip-rule="evenodd" />
              </svg>
              View on GitHub
            </a>
          </div>
          <p class="mt-6 text-sm text-gray-500">
            5 minutes to deploy • Open Source • No vendor lock-in
          </p>
        </div>
      </div>
    </section>

    <!-- Cost Comparison -->
    <section class="py-12 sm:py-16 bg-gray-50">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-8 sm:mb-12">
          <h2 class="text-2xl sm:text-3xl font-bold text-gray-900 px-4">
            Why pay $10,000/month to rent your login page?
          </h2>
          <p class="mt-3 sm:mt-4 text-base sm:text-lg text-gray-600 px-4">
            Traditional auth providers charge based on MAUs. We don't.
          </p>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 sm:gap-8">
          <!-- Traditional SaaS -->
          <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div class="text-center">
              <p class="text-sm font-medium text-gray-500 uppercase">Traditional SaaS</p>
              <p class="mt-4 text-4xl font-bold text-gray-900">$1,000+</p>
              <p class="mt-1 text-sm text-gray-500">per month</p>
              <div class="mt-6 space-y-4">
                <div class="flex items-start">
                  <svg class="h-5 w-5 text-red-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                  <span class="text-sm text-gray-700">Pricing scales with users</span>
                </div>
                <div class="flex items-start">
                  <svg class="h-5 w-5 text-red-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                  <span class="text-sm text-gray-700">Vendor lock-in</span>
                </div>
                <div class="flex items-start">
                  <svg class="h-5 w-5 text-red-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                  <span class="text-sm text-gray-700">Data on third-party servers</span>
                </div>
                <div class="flex items-start">
                  <svg class="h-5 w-5 text-red-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                  <span class="text-sm text-gray-700">Limited customization</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Self-Hosted -->
          <div class="bg-blue-50 rounded-lg shadow-sm border-2 border-blue-600 p-6 relative">
            <div class="absolute -top-3 left-1/2 transform -translate-x-1/2">
              <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-600 text-white">
                Best value
              </span>
            </div>
            <div class="text-center">
              <p class="text-sm font-medium text-blue-600 uppercase">Self-Hosted SSO</p>
              <p class="mt-4 text-4xl font-bold text-gray-900">$10</p>
              <p class="mt-1 text-sm text-gray-500">per month (VPS)</p>
              <div class="mt-6 space-y-4">
                <div class="flex items-start">
                  <svg class="h-5 w-5 text-green-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                  </svg>
                  <span class="text-sm text-gray-700">Fixed cost at any scale</span>
                </div>
                <div class="flex items-start">
                  <svg class="h-5 w-5 text-green-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                  </svg>
                  <span class="text-sm text-gray-700">Complete control</span>
                </div>
                <div class="flex items-start">
                  <svg class="h-5 w-5 text-green-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                  </svg>
                  <span class="text-sm text-gray-700">Your infrastructure</span>
                </div>
                <div class="flex items-start">
                  <svg class="h-5 w-5 text-green-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                  </svg>
                  <span class="text-sm text-gray-700">Full source access</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Scale Example -->
          <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div class="text-center">
              <p class="text-sm font-medium text-gray-500 uppercase">At 100K users</p>
              <p class="mt-4 text-4xl font-bold text-gray-900">Still $10</p>
              <p class="mt-1 text-sm text-gray-500">per month</p>
              <div class="mt-6 space-y-4">
                <div class="flex items-start">
                  <svg class="h-5 w-5 text-green-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                  </svg>
                  <span class="text-sm text-gray-700">500K-2M MAU capacity</span>
                </div>
                <div class="flex items-start">
                  <svg class="h-5 w-5 text-green-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                  </svg>
                  <span class="text-sm text-gray-700">SQLite + Rust performance</span>
                </div>
                <div class="flex items-start">
                  <svg class="h-5 w-5 text-green-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                  </svg>
                  <span class="text-sm text-gray-700">Proven in production</span>
                </div>
                <div class="flex items-start">
                  <svg class="h-5 w-5 text-green-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                  </svg>
                  <span class="text-sm text-gray-700">1 vCPU, 1GB RAM</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Features -->
    <section class="py-20">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <h2 class="text-3xl font-bold text-gray-900">
            Everything you need. Nothing you don't.
          </h2>
          <p class="mt-4 text-lg text-gray-600">
            Production-ready identity platform with enterprise features out of the box
          </p>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          <!-- Feature 1: Multi-Tenancy & Governance -->
          <div class="relative">
            <div class="flex items-center mb-4">
              <div class="flex-shrink-0">
                <div class="flex items-center justify-center h-12 w-12 rounded-md bg-blue-600 text-white">
                  <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                  </svg>
                </div>
              </div>
              <h3 class="ml-4 text-lg font-semibold text-gray-900">Multi-Tenancy & Governance</h3>
            </div>
            <p class="text-gray-600">
              Complete organization isolation with RBAC and a platform-owner approval workflow for new tenants.
            </p>
          </div>

          <!-- Feature 2: BYOO -->
          <div class="relative">
            <div class="flex items-center mb-4">
              <div class="flex-shrink-0">
                <div class="flex items-center justify-center h-12 w-12 rounded-md bg-blue-600 text-white">
                  <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
              </div>
              <h3 class="ml-4 text-lg font-semibold text-gray-900">Bring Your Own OAuth</h3>
            </div>
            <p class="text-gray-600">
              Let customers use their own OAuth credentials. Encrypted storage with AES-GCM keeps secrets safe.
            </p>
          </div>

          <!-- Feature 3: Device Flow -->
          <div class="relative">
            <div class="flex items-center mb-4">
              <div class="flex-shrink-0">
                <div class="flex items-center justify-center h-12 w-12 rounded-md bg-blue-600 text-white">
                  <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
                  </svg>
                </div>
              </div>
              <h3 class="ml-4 text-lg font-semibold text-gray-900">Device Authorization Flow</h3>
            </div>
            <p class="text-gray-600">
              Secure RFC 8628 device flow for CLIs, mobile, and IoT apps without embedded browsers.
            </p>
          </div>

          <!-- Feature 4: Analytics -->
          <div class="relative">
            <div class="flex items-center mb-4">
              <div class="flex-shrink-0">
                <div class="flex items-center justify-center h-12 w-12 rounded-md bg-blue-600 text-white">
                  <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                </div>
              </div>
              <h3 class="ml-4 text-lg font-semibold text-gray-900">Comprehensive Analytics</h3>
            </div>
            <p class="text-gray-600">
              Detailed login, growth, and activity metrics for both individual organizations and the entire platform.
            </p>
          </div>

          <!-- Feature 5: Secure Sessions -->
          <div class="relative">
            <div class="flex items-center mb-4">
              <div class="flex-shrink-0">
                <div class="flex items-center justify-center h-12 w-12 rounded-md bg-blue-600 text-white">
                  <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
              </div>
              <h3 class="ml-4 text-lg font-semibold text-gray-900">Secure Session Management</h3>
            </div>
            <p class="text-gray-600">
              JWT-based sessions with server-side revocation and secure refresh token rotation.
            </p>
          </div>

          <!-- Feature 6: SDK -->
          <div class="relative">
            <div class="flex items-center mb-4">
              <div class="flex-shrink-0">
                <div class="flex items-center justify-center h-12 w-12 rounded-md bg-blue-600 text-white">
                  <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                  </svg>
                </div>
              </div>
              <h3 class="ml-4 text-lg font-semibold text-gray-900">Developer-First SDK</h3>
            </div>
            <p class="text-gray-600">
              Zero-dependency TypeScript SDK. Strongly typed, framework-agnostic, works everywhere.
            </p>
          </div>
        </div>
      </div>
    </section>

    <!-- Tech Stack -->
    <section class="py-16 bg-gray-50">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-12">
          <h2 class="text-3xl font-bold text-gray-900">
            Built for performance and reliability
          </h2>
          <p class="mt-4 text-lg text-gray-600">
            Modern tech stack proven to scale
          </p>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h3 class="text-lg font-semibold text-gray-900 mb-3">Rust + Axum</h3>
            <p class="text-gray-600 text-sm">
              High-performance async runtime with memory safety guarantees. Production-grade error handling with comprehensive type safety.
            </p>
          </div>
          <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h3 class="text-lg font-semibold text-gray-900 mb-3">SQLite + WAL</h3>
            <p class="text-gray-600 text-sm">
              Single-file database with aggressive checkpointing. Proven to handle millions of users without breaking a sweat.
            </p>
          </div>
          <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h3 class="text-lg font-semibold text-gray-900 mb-3">Docker Ready</h3>
            <p class="text-gray-600 text-sm">
              Multi-stage builds for minimal image size. Deploy anywhere in minutes with docker-compose or your orchestrator of choice.
            </p>
          </div>
        </div>
      </div>
    </section>

    <!-- Use Cases -->
    <section class="py-20">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <h2 class="text-3xl font-bold text-gray-900">
            Who is this for?
          </h2>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div class="bg-gray-50 rounded-lg p-8">
            <h3 class="text-xl font-semibold text-gray-900 mb-4">Bootstrapped B2B SaaS</h3>
            <p class="text-gray-600 mb-4">
              Launch with multi-tenancy, org management, and SSO without paying $500+/month before you have revenue. Get enterprise features from day one.
            </p>
            <div class="text-sm text-gray-500">
              Perfect for: SaaS startups, B2B platforms, internal tools
            </div>
          </div>
          <div class="bg-gray-50 rounded-lg p-8">
            <h3 class="text-xl font-semibold text-gray-900 mb-4">Indie Hackers & Dev Tools</h3>
            <p class="text-gray-600 mb-4">
              Add GitHub/Google login plus CLI authentication in under an hour. Focus on your product, not auth infrastructure.
            </p>
            <div class="text-sm text-gray-500">
              Perfect for: CLI tools, dev platforms, side projects
            </div>
          </div>
          <div class="bg-gray-50 rounded-lg p-8">
            <h3 class="text-xl font-semibold text-gray-900 mb-4">Privacy-Conscious Teams</h3>
            <p class="text-gray-600 mb-4">
              Your user data never leaves your infrastructure. Full GDPR compliance out of the box. Complete audit trail of all access.
            </p>
            <div class="text-sm text-gray-500">
              Perfect for: Healthcare, govtech, EU startups, regulated industries
            </div>
          </div>
          <div class="bg-gray-50 rounded-lg p-8">
            <h3 class="text-xl font-semibold text-gray-900 mb-4">Open Source Projects</h3>
            <p class="text-gray-600 mb-4">
              Dual licensed (AGPL API, MIT SDK) and ready to fork. Build the next self-hosted alternative to major SaaS products with auth that just works.
            </p>
            <div class="text-sm text-gray-500">
              Perfect for: Open source apps, self-hosted alternatives, community platforms
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- CTA Section -->
    <section class="py-20 bg-blue-600">
      <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        <h2 class="text-3xl sm:text-4xl font-bold text-white">
          Deploy in 5 minutes
        </h2>
        <p class="mt-4 text-xl text-blue-100">
          Start with Docker Compose or deploy to your favorite cloud provider
        </p>
        <div class="mt-10 flex flex-col sm:flex-row gap-4 justify-center">
          <button
            @click="goToLogin"
            class="inline-flex items-center px-8 py-4 border border-transparent text-lg font-medium rounded-md text-blue-600 bg-white hover:bg-gray-50 transition-colors shadow-lg"
          >
            Get started now
            <svg class="ml-2 -mr-1 w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6" />
            </svg>
          </button>
          <a
            href="https://github.com/drmhse/sso"
            target="_blank"
            rel="noopener noreferrer"
            class="inline-flex items-center px-8 py-4 border border-white text-lg font-medium rounded-md text-white hover:bg-blue-700 transition-colors"
          >
            <svg class="mr-2 w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
              <path fill-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.203 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.942.359.31.678.921.678 1.856 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clip-rule="evenodd" />
            </svg>
            Read the docs
          </a>
        </div>
        <div class="mt-8 text-blue-100 text-sm">
          <code class="bg-blue-700 px-3 py-1 rounded">
            docker-compose up --build -d
          </code>
        </div>
      </div>
    </section>

    <!-- Footer -->
    <footer class="bg-gray-900 text-white py-12">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div>
            <h3 class="text-lg font-semibold mb-4">SSO</h3>
            <p class="text-gray-400 text-sm">
              Open-source identity platform that scales to millions of users on a $10 server.
            </p>
          </div>
          <div>
            <h4 class="text-sm font-semibold mb-4 uppercase tracking-wider">Resources</h4>
            <ul class="space-y-2">
              <li>
                <a href="https://github.com/drmhse/sso" target="_blank" rel="noopener noreferrer" class="text-gray-400 hover:text-white text-sm transition-colors">
                  Documentation
                </a>
              </li>
              <li>
                <a href="https://github.com/drmhse/sso" target="_blank" rel="noopener noreferrer" class="text-gray-400 hover:text-white text-sm transition-colors">
                  GitHub
                </a>
              </li>
              <li>
                <a href="https://github.com/drmhse/sso/issues" target="_blank" rel="noopener noreferrer" class="text-gray-400 hover:text-white text-sm transition-colors">
                  Issues
                </a>
              </li>
            </ul>
          </div>
          <div>
            <h4 class="text-sm font-semibold mb-4 uppercase tracking-wider">Product</h4>
            <ul class="space-y-2">
              <li>
                <a href="https://www.npmjs.com/package/@drmhse/sso-sdk" target="_blank" rel="noopener noreferrer" class="text-gray-400 hover:text-white text-sm transition-colors">
                  SDK
                </a>
              </li>
              <li>
                <a href="https://github.com/drmhse/sso#core-features" target="_blank" rel="noopener noreferrer" class="text-gray-400 hover:text-white text-sm transition-colors">
                  Features
                </a>
              </li>
              <li>
                <a href="https://github.com/drmhse/sso#deployment" target="_blank" rel="noopener noreferrer" class="text-gray-400 hover:text-white text-sm transition-colors">
                  Deployment
                </a>
              </li>
            </ul>
          </div>
          <div>
            <h4 class="text-sm font-semibold mb-4 uppercase tracking-wider">Legal</h4>
            <ul class="space-y-2">
              <li>
                <a href="https://github.com/drmhse/sso" target="_blank" rel="noopener noreferrer" class="text-gray-400 hover:text-white text-sm transition-colors">
                  Dual Licensed (AGPL/MIT)
                </a>
              </li>
            </ul>
          </div>
        </div>
        <div class="mt-8 pt-8 border-t border-gray-800 text-center text-sm text-gray-400">
          <p>Open source identity platform. Self-hosted and free forever.</p>
        </div>
      </div>
    </footer>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router';

const router = useRouter();

const goToLogin = () => {
  router.push({ name: 'Login' });
};
</script>
