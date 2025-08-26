import { Schema, model, models, InferSchemaType } from "mongoose";

const ROLES = ["reader", "partner", "contributor", "admin"] as const;

const SocialSchema = new Schema(
  {
    provider: { type: String, required: true }, // 'clerk' | 'okta' | 'google' | 'apple' | ...
    providerUserId: { type: String, required: true }, // stable id from the provider
    email: { type: String },
    name: { type: String },
    avatar: { type: String },
  },
  { _id: false }
);

const AccountSchema = new Schema(
  {
    role: { type: String, enum: ROLES, required: true, index: true },

    // We keep email for dedupe + linking across methods (normalize to lowercase).
    email: { type: String, required: true },
    username: { type: String }, // Readers can set usernames later, but it's optional
    partnerId: { type: String }, //  partner can log in with this and password
    // Present only if password login is allowed (partners/contributors/admins)
    passwordHash: { type: String, default: null },

    // Social/OAuth connections (Clerk/Okta/Google/etc.)
    socials: { type: [SocialSchema], default: [] },

    status: {
      type: String,
      enum: ["enabled", "disabled"],
      default: "enabled",
      index: true,
    },
    lastLoginAt: { type: Date },
  },
  { timestamps: true, versionKey: false }
);

// ---- Indexes (prevent duplicates; speed lookups) ----
AccountSchema.index({ email: 1 }, { unique: true }); // unique email index
AccountSchema.index({ username: 1 }, { unique: true, sparse: true }); // unique username index
AccountSchema.index(
  { "socials.provider": 1, "socials.providerUserId": 1 },
  { unique: true, sparse: true }
);

// Normalize email, username, and partnerId case before saving
AccountSchema.pre("save", function (next) {
  if (this.email) this.email = this.email.trim().toLowerCase();
  if (this.username) this.username = this.username.trim().toLowerCase();
  if (this.partnerId) this.partnerId = this.partnerId.trim().toLowerCase();
  next();
});

export type Account = InferSchemaType<typeof AccountSchema>;
export const AccountModel = models.Account || model("Account", AccountSchema);
