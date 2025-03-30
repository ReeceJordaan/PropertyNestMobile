import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'io.ionic.starter',
  appName: 'PropertyNest',
  webDir: 'www',
  bundledWebRuntime: false,
  server: {
    url: 'http://192.168.0.1:8100',
    cleartext: true
  },
  plugins: {
    SplashScreen: {
      launchAutoHide: false,
    }
  },
  cordova: {},
};

export default config;