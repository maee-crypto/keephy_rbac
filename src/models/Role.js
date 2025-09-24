/**
 * Role Model
 * Represents user roles with hierarchical permissions
 */

import mongoose from 'mongoose';

const permissionSchema = new mongoose.Schema({
  resource: {
    type: String,
    required: true,
    enum: [
      'organizations', 'brands', 'businesses', 'franchises', 'staff', 'forms', 
      'submissions', 'discounts', 'notifications', 'reports', 'analytics',
      'translations', 'integrations', 'exports', 'audit', 'settings', 'billing'
    ]
  },
  actions: [{
    type: String,
    enum: ['create', 'read', 'update', 'delete', 'manage', 'approve', 'export']
  }],
  conditions: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  }
});

const roleSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    enum: [
      'super_admin', 'organization_admin', 'brand_admin', 'business_admin',
      'manager', 'staff', 'analyst', 'billing'
    ]
  },
  displayName: {
    type: String,
    required: true
  },
  description: {
    type: String,
    maxlength: 500
  },
  level: {
    type: Number,
    required: true,
    min: 1,
    max: 8
  },
  scope: {
    type: String,
    required: true,
    enum: ['platform', 'organization', 'brand', 'business', 'franchise', 'location']
  },
  permissions: [permissionSchema],
  isSystemRole: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  },
  metadata: {
    createdBy: {
      type: String,
      required: true
    },
    lastModifiedBy: String,
    version: {
      type: String,
      default: '1.0'
    }
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
roleSchema.index({ name: 1 });
roleSchema.index({ level: 1 });
roleSchema.index({ scope: 1 });
roleSchema.index({ isActive: 1 });

// Pre-save middleware
roleSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

// Methods
roleSchema.methods.hasPermission = function(resource, action) {
  const permission = this.permissions.find(p => p.resource === resource);
  if (!permission) return false;
  return permission.actions.includes(action);
};

roleSchema.methods.canAccess = function(resource, action, context = {}) {
  if (!this.hasPermission(resource, action)) return false;
  
  // Check scope-based access
  const permission = this.permissions.find(p => p.resource === resource);
  if (permission && permission.conditions) {
    for (const [key, value] of permission.conditions) {
      if (context[key] !== value) return false;
    }
  }
  
  return true;
};

// Static methods
roleSchema.statics.getByLevel = function(level) {
  return this.find({ level, isActive: true }).sort({ name: 1 });
};

roleSchema.statics.getByScope = function(scope) {
  return this.find({ scope, isActive: true }).sort({ level: 1 });
};

roleSchema.statics.getSystemRoles = function() {
  return this.find({ isSystemRole: true, isActive: true }).sort({ level: 1 });
};

export default mongoose.model('Role', roleSchema);
