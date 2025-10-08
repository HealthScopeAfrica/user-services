import mongoose, { Schema, Document } from "mongoose";

export interface IArticle extends Document {
	title: string;
	content: string;
	summary?: string; // Brief description for list views
	tags: string[];
	category?: string; // e.g., "Mental Health", "Nutrition", "Disease Prevention"
	author: mongoose.Types.ObjectId; // Reference to contributor/author
	status: "draft" | "review" | "published" | "archived"; // Publishing workflow
	featuredImage?: string; // URL to cover image
	audioUrl?: string; // URL to audio version (for accessibility)
	language: string; // e.g., "en", "sw", "ha", "am" for multilingual support

	// Engagement metrics
	views: number;
	likes: number;
	shares: number;
	readTime?: number; // Estimated reading time in minutes

	// SEO & Discovery
	slug?: string; // URL-friendly version of title
	metaDescription?: string;

	// Moderation & Quality
	verifiedBy?: mongoose.Types.ObjectId; // Super contributor who verified
	verifiedAt?: Date;
	reportCount: number; // For flagged content

	// Timestamps
	publishedAt?: Date;
	createdAt: Date;
	updatedAt: Date;
}

const ArticleSchema = new Schema<IArticle>(
	{
		title: {
			type: String,
			required: true,
			trim: true,
			maxlength: 200,
		},
		content: {
			type: String,
			required: true,
		},
		summary: {
			type: String,
			trim: true,
			maxlength: 300,
		},
		tags: {
			type: [String],
			default: [],
			index: true,
		},
		category: {
			type: String,
			enum: [
				"Mental Health",
				"Nutrition",
				"Disease Prevention",
				"Maternal Health",
				"Child Health",
				"Infectious Diseases",
				"Chronic Conditions",
				"Fitness & Wellness",
				"Sexual Health",
				"Traditional Medicine",
				"Public Health",
				"Emergency Care",
				"General Health",
			],
			index: true,
		},
		author: {
			type: Schema.Types.ObjectId,
			ref: "Account", // or "ContributorProfile" based on your schema
			required: true,
			index: true,
		},
		status: {
			type: String,
			enum: ["draft", "review", "published", "archived"],
			default: "draft",
			index: true,
		},
		featuredImage: {
			type: String,
			trim: true,
		},
		audioUrl: {
			type: String,
			trim: true,
		},
		language: {
			type: String,
			default: "en",
			enum: ["en", "sw", "ha", "am", "yo", "ig", "fr", "ar"], // African languages
			index: true,
		},

		// Engagement metrics
		views: {
			type: Number,
			default: 0,
			index: true,
		},
		likes: {
			type: Number,
			default: 0,
		},
		shares: {
			type: Number,
			default: 0,
		},
		readTime: {
			type: Number, // in minutes
			default: 5,
		},

		// SEO
		slug: {
			type: String,
			unique: true,
			sparse: true, // Allows null values
			trim: true,
			lowercase: true,
		},
		metaDescription: {
			type: String,
			maxlength: 160,
		},

		// Moderation
		verifiedBy: {
			type: Schema.Types.ObjectId,
			ref: "Account",
		},
		verifiedAt: {
			type: Date,
		},
		reportCount: {
			type: Number,
			default: 0,
		},

		publishedAt: {
			type: Date,
			index: true,
		},
	},
	{
		timestamps: true,
		toJSON: { virtuals: true },
		toObject: { virtuals: true },
	}
);

// Indexes for performance
ArticleSchema.index({ status: 1, createdAt: -1 });
ArticleSchema.index({ status: 1, category: 1 });
ArticleSchema.index({ status: 1, views: -1 });
ArticleSchema.index({ status: 1, publishedAt: -1 });
ArticleSchema.index({ language: 1, status: 1 });

// Text search index
ArticleSchema.index({
	title: "text",
	summary: "text",
	content: "text",
	tags: "text",
});

// Pre-save middleware to generate slug
ArticleSchema.pre("save", function (next) {
	if (this.isModified("title") && !this.slug) {
		this.slug = this.title
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, "-")
			.replace(/(^-|-$)/g, "");
	}

	// Set publishedAt when status changes to published
	if (
		this.isModified("status") &&
		this.status === "published" &&
		!this.publishedAt
	) {
		this.publishedAt = new Date();
	}

	// Calculate read time based on content (average 200 words/minute)
	if (this.isModified("content")) {
		const wordCount = this.content.split(/\s+/).length;
		this.readTime = Math.ceil(wordCount / 200);
	}

	next();
});

// Virtual for checking if article is new (published within last 7 days)
ArticleSchema.virtual("isNew").get(function () {
	if (!this.publishedAt) return false;
	const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
	return this.publishedAt > sevenDaysAgo;
});

export default mongoose.model<IArticle>("Article", ArticleSchema);
