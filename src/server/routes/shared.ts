import { Router } from 'express';
import { requireAuth } from '../auth.ts';
import { sharedState, connectedClients, getActiveOperators, applyStateMutation } from '../state.ts';

export const sharedRouter = Router();

// GET /api/shared/state
sharedRouter.get('/state', (req, res) => {
  res.json({
    success: true,
    state: {
      ...sharedState,
      activeUsersCount: Math.max(1, connectedClients.size),
      activeOperators: getActiveOperators(),
    },
  });
});

// POST /api/shared/mutate
sharedRouter.post('/mutate', requireAuth, (req, res) => {
  const { action, payload, operator } = req.body;
  if (!action) {
    return res.status(400).json({ success: false, error: 'Action requise.' });
  }
  applyStateMutation(action, payload, operator);
  res.json({
    success: true,
    state: {
      ...sharedState,
      activeUsersCount: Math.max(1, connectedClients.size),
      activeOperators: getActiveOperators(),
    },
  });
});
