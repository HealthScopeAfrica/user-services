import { Schema, model, models, InferSchemaType } from "mongoose";

const TIERS = ["standard", "featured"] as const;
const PARTNER_STATUS = ["pending", "approved", "rejected"] as const;

const PartnerProfileSchema = new Schema(
  {
    accountId: { type: Schema.Types.ObjectId, ref: "Account", index: true }, // null until approved
    organization: {
      name: { type: String, required: true },
      ShortName: { type: String }, //abbreviation
      regNumber: { type: String },
      type: { type: String }, // NGO, Foundation, Others etc.
      address: { type: String },
      country: { type: String },
      hqCity: { type: String },
      email: { type: String, required: true },
      phone: { type: String },
      website: { type: String },
      logoUrl: { type: String },
    },

    contactPerson: {
      firstName: { type: String },
      lastName: { type: String },
      role: { type: String },
      phone: { type: String },
      email: { type: String },
    },

    tier: { type: String, enum: TIERS, default: "standard" },
    status: {
      type: String,
      enum: PARTNER_STATUS,
      default: "pending",
      index: true,
    },
  },
  { timestamps: true, versionKey: false }
);

// One Account ↔ one PartnerProfile (sparse because pending partners may not have account yet)
PartnerProfileSchema.index({ accountId: 1 }, { unique: true, sparse: true });

export type PartnerProfile = InferSchemaType<typeof PartnerProfileSchema>;
export const PartnerProfileModel =
  models.PartnerProfile || model("PartnerProfile", PartnerProfileSchema, "partners");
