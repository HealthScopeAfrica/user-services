import { Schema, model, models, InferSchemaType } from "mongoose";

const LEVELS = ["basic", "super"] as const;
const STATUSES = ["active", "suspended"] as const;

const ContributorProfileSchema = new Schema(
  {
    accountId: {
      type: Schema.Types.ObjectId,
      ref: "Account",
      required: true,
      index: true,
    },
    invitedBy: {
      type: Schema.Types.ObjectId,
      ref: "PartnerProfile",
      required: true,
      index: true,
    }, // owning partner org
    level: { type: String, enum: LEVELS, default: "basic", index: true },
    profession: { type: String },
    credentialsUrl: { type: String }, //if partner wants to see your contribution credentials
    bio: { type: String }, //short description about you
    status: { type: String, enum: STATUSES, default: "active", index: true }, //can be toggled by partner and admin
    lastActiveAt: { type: Date }, //when was the last time you contributed
  },
  { timestamps: true, versionKey: false }
);

// Prevent duplicate membership to the same partner
// Enforce: one contributor profile per account (=> only one partner)
ContributorProfileSchema.index({ accountId: 1 }, { unique: true });

// For dashboards/queries (one partner -> many contributors)
ContributorProfileSchema.index({ invitedBy: 1 });
export type ContributorProfile = InferSchemaType<
  typeof ContributorProfileSchema
>;
export const ContributorProfileModel =
  models.ContributorProfile ||
  model("ContributorProfile", ContributorProfileSchema, "contributors");
