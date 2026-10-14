import { Router } from 'express';
import { requireAuth } from '../auth.ts';

export function createSharedRouter(
  getSharedState: () => any,
  applyMutation: (action: string, payload: any, operator: any) => void
): Router {
  const router = Router();

  // GET /api/shared/state
  router.get('/state', (req, res) => {
    res.json({
      success: true,
      state: getSharedState(),
    });
  });

  // POST /api/shared/mutate
  router.post('/mutate', requireAuth, (req, res) => {
    const { action, payload, operator } = req.body;
    if (!action) {
      return res.status(400).json({ success: false, error: 'Action required' });
    }
    applyMutation(action, payload, operator);
    res.json({ success: true, state: getSharedState() });
  });

  return router;
}
