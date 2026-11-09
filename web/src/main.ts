import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { ElButton, ElOption, ElSelect } from 'element-plus'
import 'element-plus/dist/index.css'
import App from './App.vue'
import { router } from './router'
import './style.css'

createApp(App).use(createPinia()).use(router)
  .component('ElButton', ElButton).component('ElOption', ElOption)
  .component('ElSelect', ElSelect).mount('#app')
