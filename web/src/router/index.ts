import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'

export const router = createRouter({ history: createWebHistory(import.meta.env.BASE_URL), routes: [{ path: '/', component: Dashboard }] })
