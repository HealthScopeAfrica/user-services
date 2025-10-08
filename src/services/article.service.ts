import Article from "../models/article.model";
import { ReaderProfileModel } from "../models/users/reader-profile.model";

interface ArticleFilters {
	category?: string;
	tags?: string[];
	sortBy?: string;
	order?: string;
}

interface PaginatedResult {
	articles: any[];
	totalArticles: number;
	totalPages: number;
	hasNext: boolean;
	hasPrev: boolean;
}

class ArticleService {
	// Fetch all articles with pagination and filters
	getAllArticles = async (
		page: number = 1,
		limit: number = 10,
		filters: ArticleFilters = {}
	): Promise<PaginatedResult> => {
		const skip = (page - 1) * limit;
		const query: any = { status: "published" }; // Only published articles

		// Apply category filter
		if (filters.category) {
			query.category = filters.category;
		}

		// Apply tags filter
		if (filters.tags && filters.tags.length > 0) {
			query.tags = { $in: filters.tags };
		}

		// Build sort object
		const sortField = filters.sortBy || "createdAt";
		const sortOrder = filters.order === "asc" ? 1 : -1;
		const sort: any = { [sortField]: sortOrder };

		const [articles, totalArticles] = await Promise.all([
			Article.find(query)
				.sort(sort)
				.skip(skip)
				.limit(limit)
				.select("-content") // Exclude full content for list view
				.populate("author", "name profilePicture") // Populate author details
				.lean(),
			Article.countDocuments(query),
		]);

		const totalPages = Math.ceil(totalArticles / limit);

		return {
			articles,
			totalArticles,
			totalPages,
			hasNext: page < totalPages,
			hasPrev: page > 1,
		};
	};

	// Fetch single article by ID with optional user context
	getArticleById = async (id: string, userId?: string) => {
		const article = await Article.findById(id)
			.populate("author", "name profilePicture bio")
			.lean();

		if (!article) return null;

		// Check if article is in user's favourites
		// if (userId) {
		// 	const user = await ReaderProfileModel.findById(userId).select(
		// 		"favourites"
		// 	);
		// 	// article.isFavourited = user?.favourites?.includes(id) || false;
		// }

		return article;
	};

	// Search articles by query (title, summary, content, tags)
	searchArticles = async (
		query: string,
		page: number = 1,
		limit: number = 10
	): Promise<PaginatedResult> => {
		const skip = (page - 1) * limit;

		const searchQuery = {
			status: "published",
			$or: [
				{ title: { $regex: query, $options: "i" } },
				{ summary: { $regex: query, $options: "i" } },
				{ content: { $regex: query, $options: "i" } },
				{ tags: { $regex: query, $options: "i" } },
			],
		};

		const [articles, totalArticles] = await Promise.all([
			Article.find(searchQuery)
				.sort({ relevanceScore: -1, createdAt: -1 }) // Sort by relevance
				.skip(skip)
				.limit(limit)
				.select("-content")
				.populate("author", "name profilePicture")
				.lean(),
			Article.countDocuments(searchQuery),
		]);

		const totalPages = Math.ceil(totalArticles / limit);

		return {
			articles,
			totalArticles,
			totalPages,
			hasNext: page < totalPages,
			hasPrev: page > 1,
		};
	};

	// Fetch recommended articles for a user based on interests and reading history
	getRecommendedArticles = async (userId: string, limit: number = 10) => {
		const user = await ReaderProfileModel.findById(userId).select(
			"interests readingHistory"
		);
		if (!user) return [];

		// Build recommendation query
		const query: any = {
			status: "published",
			_id: { $nin: user.readingHistory || [] }, // Exclude already read articles
		};

		// Match user interests with article tags
		if (user.interests && user.interests.length > 0) {
			query.tags = { $in: user.interests };
		}

		const articles = await Article.find(query)
			.sort({ views: -1, createdAt: -1 }) // Popular recent articles
			.limit(limit)
			.select("-content")
			.populate("author", "name profilePicture")
			.lean();

		return articles;
	};

	// Get trending articles based on views and engagement within timeframe
	getTrendingArticles = async (
		limit: number = 10,
		timeframe: string = "week"
	) => {
		const now = new Date();
		let startDate: Date;

		switch (timeframe) {
			case "day":
				startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
				break;
			case "month":
				startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
				break;
			default: // week
				startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
		}

		const articles = await Article.find({
			status: "published",
			createdAt: { $gte: startDate },
		})
			.sort({ views: -1, shares: -1, likes: -1 })
			.limit(limit)
			.select("-content")
			.populate("author", "name profilePicture")
			.lean();

		return articles;
	};

	// Get articles by category
	getArticlesByCategory = async (
		category: string,
		page: number = 1,
		limit: number = 10
	): Promise<PaginatedResult> => {
		const skip = (page - 1) * limit;

		const [articles, totalArticles] = await Promise.all([
			Article.find({ status: "published", category })
				.sort({ createdAt: -1 })
				.skip(skip)
				.limit(limit)
				.select("-content")
				.populate("author", "name profilePicture")
				.lean(),
			Article.countDocuments({ status: "published", category }),
		]);

		const totalPages = Math.ceil(totalArticles / limit);

		return {
			articles,
			totalArticles,
			totalPages,
			hasNext: page < totalPages,
			hasPrev: page > 1,
		};
	};

	// Get articles by tag
	getArticlesByTag = async (
		tag: string,
		page: number = 1,
		limit: number = 10
	): Promise<PaginatedResult> => {
		const skip = (page - 1) * limit;

		const [articles, totalArticles] = await Promise.all([
			Article.find({ status: "published", tags: tag })
				.sort({ createdAt: -1 })
				.skip(skip)
				.limit(limit)
				.select("-content")
				.populate("author", "name profilePicture")
				.lean(),
			Article.countDocuments({ status: "published", tags: tag }),
		]);

		const totalPages = Math.ceil(totalArticles / limit);

		return {
			articles,
			totalArticles,
			totalPages,
			hasNext: page < totalPages,
			hasPrev: page > 1,
		};
	};

	// Save an article to user's favourites
	saveArticleToFavourites = async (userId: string, articleId: string) => {
		// Verify article exists
		const article = await Article.findById(articleId);
		if (!article) throw new Error("Article not found");

		const user = await ReaderProfileModel.findById(userId);
		if (!user) throw new Error("User not found");

		if (user.favourites.includes(articleId)) {
			throw new Error("Article already in favourites");
		}

		user.favourites.push(articleId);
		await user.save();

		return user;
	};

	// Remove an article from user's favourites
	removeArticleFromFavourites = async (userId: string, articleId: string) => {
		const user = await ReaderProfileModel.findById(userId);
		if (!user) throw new Error("User not found");

		user.favourites = user.favourites.filter(
			(id: string) => id.toString() !== articleId
		);
		await user.save();

		return user;
	};

	// Get user's favourite articles
	getFavouriteArticles = async (
		userId: string,
		page: number = 1,
		limit: number = 10
	): Promise<PaginatedResult> => {
		const skip = (page - 1) * limit;

		const user = await ReaderProfileModel.findById(userId).select(
			"favourites"
		);
		if (!user) throw new Error("User not found");

		const totalArticles = user.favourites.length;
		const paginatedFavourites = user.favourites.slice(skip, skip + limit);

		const articles = await Article.find({
			_id: { $in: paginatedFavourites },
			status: "published",
		})
			.select("-content")
			.populate("author", "name profilePicture")
			.lean();

		const totalPages = Math.ceil(totalArticles / limit);

		return {
			articles,
			totalArticles,
			totalPages,
			hasNext: page < totalPages,
			hasPrev: page > 1,
		};
	};

	// Track article view for analytics
	incrementArticleView = async (articleId: string, userId?: string) => {
		// Increment view count
		await Article.findByIdAndUpdate(articleId, {
			$inc: { views: 1 },
		});

		// Optionally track user reading history
		if (userId) {
			await ReaderProfileModel.findByIdAndUpdate(userId, {
				$addToSet: { readingHistory: articleId }, // Prevents duplicates
				$set: { lastActive: new Date() },
			});
		}

		return true;
	};
}

export default new ArticleService();
