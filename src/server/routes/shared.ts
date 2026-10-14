import { Router } from 'express';
import { requireAuth, resolveAuthenticatedOperator } from '../auth.ts';
import { sharedState, connectedClients, getActiveOperators, applyStateMutation } from '../state.ts';
import { sharedMutateSchema, validateBody } from '../validators.ts';

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

// POST /api/shared/mutate (SECURED: requireAuth + validateBody(sharedMutateSchema))
sharedRouter.post('/mutate', requireAuth, validateBody(sharedMutateSchema), (req, res) => {
  const { action, payload } = req.body;
  const authenticatedOp = (req as any).authenticatedOperator || resolveAuthenticatedOperator(req);
  applyStateMutation(action, payload, authenticatedOp);
  res.json({
    success: true,
    state: {
      ...sharedState,
      activeUsersCount: Math.max(1, connectedClients.size),
      activeOperators: getActiveOperators(),
    },
  });
});
