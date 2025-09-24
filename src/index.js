/**
 * Keephy RBAC Service
 * Centralized Role-Based Access Control with hierarchical permissions
 */

import express from 'express';
import mongoose from 'mongoose';
import pino from 'pino';
import pinoHttp from 'pino-http';
import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';

import Role from './models/Role.js';
import UserRole from './models/UserRole.js';

dotenv.config();

const app = express();
const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

// Middleware
app.use(express.json());
app.use(pinoHttp({ logger }));
app.use(helmet());
app.use(cors());

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/keephy_rbac';
mongoose.connect(MONGO_URI)
  .then(() => logger.info('Connected to MongoDB'))
  .catch(err => {
    logger.error('MongoDB connection error:', err);
    process.exit(1);
  });

// JWT verification middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Permission check middleware
const checkPermission = (resource, action) => {
  return async (req, res, next) => {
    try {
      const userRoles = await UserRole.getUserRoles(req.user.userId);
      const hasPermission = userRoles.some(userRole => {
        if (!userRole.isValid()) return false;
        return userRole.roleId.hasPermission(resource, action);
      });

      if (!hasPermission) {
        return res.status(403).json({ 
          error: 'Insufficient permissions',
          required: `${resource}:${action}`
        });
      }

      next();
    } catch (error) {
      logger.error('Permission check error:', error);
      return res.status(500).json({ error: 'Permission check failed' });
    }
  };
};

// Role Management
app.post('/roles', verifyToken, checkPermission('settings', 'create'), async (req, res) => {
  try {
    const role = new Role({
      ...req.body,
      metadata: {
        ...req.body.metadata,
        createdBy: req.user.userId
      }
    });
    
    await role.save();
    logger.info({ roleId: role._id }, 'Role created');
    res.status(201).json(role);
  } catch (error) {
    logger.error('Role creation error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.get('/roles', verifyToken, checkPermission('settings', 'read'), async (req, res) => {
  try {
    const { level, scope, isActive = true } = req.query;
    const query = { isActive };
    
    if (level) query.level = parseInt(level);
    if (scope) query.scope = scope;
    
    const roles = await Role.find(query).sort({ level: 1, name: 1 });
    res.json(roles);
  } catch (error) {
    logger.error('Roles fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch roles' });
  }
});

app.get('/roles/:id', verifyToken, checkPermission('settings', 'read'), async (req, res) => {
  try {
    const role = await Role.findById(req.params.id);
    if (!role) {
      return res.status(404).json({ error: 'Role not found' });
    }
    res.json(role);
  } catch (error) {
    logger.error('Role fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch role' });
  }
});

app.patch('/roles/:id', verifyToken, checkPermission('settings', 'update'), async (req, res) => {
  try {
    const role = await Role.findByIdAndUpdate(
      req.params.id,
      { 
        ...req.body,
        'metadata.lastModifiedBy': req.user.userId,
        updatedAt: new Date()
      },
      { new: true, runValidators: true }
    );
    
    if (!role) {
      return res.status(404).json({ error: 'Role not found' });
    }
    
    logger.info({ roleId: role._id }, 'Role updated');
    res.json(role);
  } catch (error) {
    logger.error('Role update error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.delete('/roles/:id', verifyToken, checkPermission('settings', 'delete'), async (req, res) => {
  try {
    const role = await Role.findByIdAndUpdate(
      req.params.id,
      { isActive: false, updatedAt: new Date() },
      { new: true }
    );
    
    if (!role) {
      return res.status(404).json({ error: 'Role not found' });
    }
    
    logger.info({ roleId: role._id }, 'Role deactivated');
    res.json({ message: 'Role deactivated successfully' });
  } catch (error) {
    logger.error('Role deletion error:', error);
    res.status(500).json({ error: 'Failed to deactivate role' });
  }
});

// User Role Assignment
app.post('/user-roles', verifyToken, checkPermission('settings', 'manage'), async (req, res) => {
  try {
    const userRole = new UserRole({
      ...req.body,
      assignedBy: req.user.userId
    });
    
    await userRole.save();
    await userRole.populate('roleId');
    
    logger.info({ userRoleId: userRole._id }, 'User role assigned');
    res.status(201).json(userRole);
  } catch (error) {
    logger.error('User role assignment error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.get('/user-roles', verifyToken, checkPermission('settings', 'read'), async (req, res) => {
  try {
    const { userId, roleId, scope, isActive = true } = req.query;
    const query = { isActive };
    
    if (userId) query.userId = userId;
    if (roleId) query.roleId = roleId;
    if (scope) {
      query['scope.type'] = scope;
    }
    
    const userRoles = await UserRole.find(query)
      .populate('roleId')
      .populate('userId', 'name email')
      .sort({ assignedAt: -1 });
    
    res.json(userRoles);
  } catch (error) {
    logger.error('User roles fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch user roles' });
  }
});

app.delete('/user-roles/:id', verifyToken, checkPermission('settings', 'manage'), async (req, res) => {
  try {
    const userRole = await UserRole.findByIdAndUpdate(
      req.params.id,
      { isActive: false, updatedAt: new Date() },
      { new: true }
    );
    
    if (!userRole) {
      return res.status(404).json({ error: 'User role not found' });
    }
    
    logger.info({ userRoleId: userRole._id }, 'User role deactivated');
    res.json({ message: 'User role deactivated successfully' });
  } catch (error) {
    logger.error('User role deletion error:', error);
    res.status(500).json({ error: 'Failed to deactivate user role' });
  }
});

// Permission Check Endpoint
app.post('/check-permission', verifyToken, async (req, res) => {
  try {
    const { resource, action, context = {} } = req.body;
    
    if (!resource || !action) {
      return res.status(400).json({ error: 'Resource and action are required' });
    }
    
    const userRoles = await UserRole.getUserRoles(req.user.userId);
    const hasPermission = userRoles.some(userRole => {
      if (!userRole.isValid()) return false;
      return userRole.roleId.canAccess(resource, action, context);
    });
    
    res.json({ 
      hasPermission,
      resource,
      action,
      context
    });
  } catch (error) {
    logger.error('Permission check error:', error);
    res.status(500).json({ error: 'Permission check failed' });
  }
});

// Get User Effective Permissions
app.get('/user-permissions/:userId', verifyToken, checkPermission('settings', 'read'), async (req, res) => {
  try {
    const permissions = await UserRole.getEffectivePermissions(req.params.userId);
    res.json(permissions);
  } catch (error) {
    logger.error('User permissions fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch user permissions' });
  }
});

// Health endpoints
app.get('/healthz', (req, res) => res.json({ status: 'ok' }));
app.get('/ready', (req, res) => {
  const state = mongoose.connection.readyState;
  res.status(state === 1 ? 200 : 503).json({ ready: state === 1 });
});

// Error handling middleware
app.use((error, req, res, next) => {
  logger.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

const port = Number(process.env.PORT || 3001);
app.listen(port, () => logger.info({ port }, 'keephy_rbac service listening'));

export default app;
