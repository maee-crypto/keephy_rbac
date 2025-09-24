/**
 * UserRole Model
 * Represents user role assignments with scope and context
 */

import mongoose from 'mongoose';

const userRoleSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  roleId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role',
    required: true,
    index: true
  },
  scope: {
    type: {
      type: String,
      required: true,
      enum: ['platform', 'organization', 'brand', 'business', 'franchise', 'location']
    },
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Organization',
      default: null
    },
    brandId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Brand',
      default: null
    },
    businessId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Business',
      default: null
    },
    franchiseId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Franchise',
      default: null
    }
  },
  isActive: {
    type: Boolean,
    default: true
  },
  assignedBy: {
    type: String,
    required: true
  },
  assignedAt: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date,
    default: null
  },
  metadata: {
    reason: String,
    notes: String,
    tags: [String]
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

// Compound indexes
userRoleSchema.index({ userId: 1, isActive: 1 });
userRoleSchema.index({ roleId: 1, isActive: 1 });
userRoleSchema.index({ 'scope.organizationId': 1, isActive: 1 });
userRoleSchema.index({ 'scope.businessId': 1, isActive: 1 });
userRoleSchema.index({ 'scope.franchiseId': 1, isActive: 1 });
userRoleSchema.index({ assignedAt: -1 });

// Pre-save middleware
userRoleSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

// Methods
userRoleSchema.methods.isExpired = function() {
  return this.expiresAt && new Date() > this.expiresAt;
};

userRoleSchema.methods.isValid = function() {
  return this.isActive && !this.isExpired();
};

userRoleSchema.methods.getEffectiveScope = function() {
  return {
    type: this.scope.type,
    organizationId: this.scope.organizationId,
    brandId: this.scope.brandId,
    businessId: this.scope.businessId,
    franchiseId: this.scope.franchiseId
  };
};

// Static methods
userRoleSchema.statics.getUserRoles = function(userId, includeExpired = false) {
  const query = { userId, isActive: true };
  if (!includeExpired) {
    query.$or = [
      { expiresAt: null },
      { expiresAt: { $gt: new Date() } }
    ];
  }
  return this.find(query).populate('roleId');
};

userRoleSchema.statics.getUsersByRole = function(roleId, scope = {}) {
  const query = { roleId, isActive: true };
  if (scope.organizationId) query['scope.organizationId'] = scope.organizationId;
  if (scope.brandId) query['scope.brandId'] = scope.brandId;
  if (scope.businessId) query['scope.businessId'] = scope.businessId;
  if (scope.franchiseId) query['scope.franchiseId'] = scope.franchiseId;
  
  return this.find(query).populate('userId');
};

userRoleSchema.statics.getEffectivePermissions = async function(userId, context = {}) {
  const userRoles = await this.getUserRoles(userId);
  const permissions = new Map();
  
  for (const userRole of userRoles) {
    if (!userRole.isValid()) continue;
    
    const role = userRole.roleId;
    if (!role) continue;
    
    for (const permission of role.permissions) {
      const key = `${permission.resource}:${permission.actions.join(',')}`;
      if (!permissions.has(key)) {
        permissions.set(key, {
          resource: permission.resource,
          actions: permission.actions,
          conditions: permission.conditions,
          scope: userRole.getEffectiveScope()
        });
      }
    }
  }
  
  return Array.from(permissions.values());
};

export default mongoose.model('UserRole', userRoleSchema);
