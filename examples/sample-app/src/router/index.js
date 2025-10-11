import { createRouter, createWebHistory } from 'vue-router';
import Home from '../views/Home.vue';
import Activate from '../views/Activate.vue';
import ActivateSuccess from '../views/ActivateSuccess.vue';

const routes = [
  {
    path: '/',
    name: 'Home',
    component: Home,
  },
  {
    path: '/activate',
    name: 'Activate',
    component: Activate,
  },
  {
    path: '/activate/success',
    name: 'ActivateSuccess',
    component: ActivateSuccess,
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;
