import { Schema, model, models, InferSchemaType } from "mongoose";

const ReaderProfileSchema = new Schema(
	{
		accountId: {
			type: Schema.Types.ObjectId,
			ref: "Account",
			required: true,
		},

		firstName: String,
		lastName: String,
		// preferences / interests can be added later
		dateOfBirth: Date,
		gender: String,
		phone: String,
		address: String,
		bloodGroup: String,
		allergies: [String],
		conditions: [String],
		medications: [String],
		emergencyContacts: [
			{
				name: String,
				relation: String,
				phone: String,
			},
		],
	},
	{ timestamps: true, versionKey: false }
);

ReaderProfileSchema.index({ accountId: 1 }, { unique: true }); // unique index on accountId to ensure one profile per account

export type ReaderProfile = InferSchemaType<typeof ReaderProfileSchema>;
export const ReaderProfileModel =
  models.ReaderProfile || model("ReaderProfile", ReaderProfileSchema, "readers");

