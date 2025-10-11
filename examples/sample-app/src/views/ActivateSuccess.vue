<template>
  <div class="container">
    <div class="success-box">
      <div class="icon-wrapper">
        <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
        </svg>
      </div>
      <h1>Device Authorized</h1>
      <p>
        Your device has been successfully authorized. You can now close this window and return to your application.
      </p>
    </div>
  </div>
</template>

<style scoped>
.container {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background-color: #f8f9fa;
}
.success-box {
  max-width: 500px;
  padding: 40px;
  text-align: center;
  background: white;
  border-radius: 8px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}
.icon-wrapper {
  margin: 0 auto 20px;
  width: 64px;
  height: 64px;
  border-radius: 50%;
  background-color: #e6f7ec;
  display: flex;
  align-items: center;
  justify-content: center;
}
.icon {
  width: 32px;
  height: 32px;
  color: #28a745;
}
h1 {
  font-size: 24px;
  font-weight: bold;
  color: #333;
  margin-bottom: 10px;
}
p {
  color: #666;
  line-height: 1.6;
}
</style>