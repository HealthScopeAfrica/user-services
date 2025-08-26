import { Schema, model, models, InferSchemaType } from "mongoose";

// Define the schema for AdminProfile
const AdminProfileSchema = new Schema(
  {
    // Reference to the associated account
    accountId: {
      type: Schema.Types.ObjectId,
      ref: "Account",
      required: true,
      index: true,
    },
  },
  {
    timestamps: true,       // Automatically adds createdAt and updatedAt fields
    versionKey: false,      // Disables __v version key in documents
  }
);

// Enforce: one admin profile per account (unique constraint)
AdminProfileSchema.index({ accountId: 1 }, { unique: true });

// TypeScript helper for schema inference
export type AdminProfile = InferSchemaType<typeof AdminProfileSchema>;

// Export the model, reuse if already compiled
export const AdminProfileModel =
  models.AdminProfile || model("AdminProfile", AdminProfileSchema, "admins");
