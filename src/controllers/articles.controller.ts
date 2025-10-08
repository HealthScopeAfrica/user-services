// Enhanced controller for article-related requests
import { Response } from "express";
import { AuthRequest } from "../middlewares/auth.middleware";
import articleService from "../services/article.service";

// Fetch all articles with pagination and filters
export const getArticles = async (req: AuthRequest, res: Response) => {
	try {
		const page = parseInt(req.query.page as string) || 1;
		const limit = parseInt(req.query.limit as string) || 10;
		const category = req.query.category as string;
		const tags = req.query.tags as string; // comma-separated
		const sortBy = (req.query.sortBy as string) || "createdAt"; // createdAt, views, title
		const order = (req.query.order as string) || "desc"; // asc, desc

		const filters = {
			category,
			tags: tags ? tags.split(",") : undefined,
			sortBy,
			order,
		};

		const result = await articleService.getAllArticles(page, limit, filters);

		res.json({
			success: true,
			data: result.articles,
			pagination: {
				currentPage: page,
				totalPages: result.totalPages,
				totalArticles: result.totalArticles,
				hasNext: result.hasNext,
				hasPrev: result.hasPrev,
			},
		});
	} catch (error) {
		console.error("Error fetching articles:", error);
		res.status(500).json({
			success: false,
			error: "Failed to fetch articles",
		});
	}
};

// Fetch a specific article by ID
export const getArticleById = async (req: AuthRequest, res: Response) => {
	const { id } = req.params;
	const userId = req.user?._id || req.user?.id;

	try {
		const article = await articleService.getArticleById(id, userId);

		if (!article) {
			return res.status(404).json({
				success: false,
				error: "Article not found",
			});
		}

		res.json({
			success: true,
			data: article,
		});
	} catch (error) {
		console.error(`Error fetching article with ID ${id}:`, error);
		res.status(500).json({
			success: false,
			error: "Failed to fetch article",
		});
	}
};

// Search articles by query
export const searchArticles = async (req: AuthRequest, res: Response) => {
	try {
		const query = req.query.q as string;
		const page = parseInt(req.query.page as string) || 1;
		const limit = parseInt(req.query.limit as string) || 10;

		if (!query || query.trim().length < 2) {
			return res.status(400).json({
				success: false,
				error: "Search query must be at least 2 characters",
			});
		}

		const result = await articleService.searchArticles(query, page, limit);

		res.json({
			success: true,
			data: result.articles,
			pagination: {
				currentPage: page,
				totalPages: result.totalPages,
				totalArticles: result.totalArticles,
			},
		});
	} catch (error) {
		console.error("Error searching articles:", error);
		res.status(500).json({
			success: false,
			error: "Failed to search articles",
		});
	}
};

// Fetch recommended articles for authenticated user
export const getRecommendedArticles = async (
	req: AuthRequest,
	res: Response
) => {
	const userId = req.user?._id || req.user?.id;

	try {
		if (!userId) {
			return res.status(401).json({
				success: false,
				error: "Authentication required",
			});
		}

		const limit = parseInt(req.query.limit as string) || 10;
		const recommendedArticles = await articleService.getRecommendedArticles(
			userId,
			limit
		);

		res.json({
			success: true,
			data: recommendedArticles,
		});
	} catch (error) {
		console.error(
			`Error fetching recommended articles for user ${userId}:`,
			error
		);
		res.status(500).json({
			success: false,
			error: "Failed to fetch recommendations",
		});
	}
};

// Get trending articles based on views and engagement
export const getTrendingArticles = async (req: AuthRequest, res: Response) => {
	try {
		const limit = parseInt(req.query.limit as string) || 10;
		const timeframe = (req.query.timeframe as string) || "week"; // day, week, month

		const trendingArticles = await articleService.getTrendingArticles(
			limit,
			timeframe
		);

		res.json({
			success: true,
			data: trendingArticles,
		});
	} catch (error) {
		console.error("Error fetching trending articles:", error);
		res.status(500).json({
			success: false,
			error: "Failed to fetch trending articles",
		});
	}
};

// Get articles by category
export const getArticlesByCategory = async (
	req: AuthRequest,
	res: Response
) => {
	const { category } = req.params;
	const page = parseInt(req.query.page as string) || 1;
	const limit = parseInt(req.query.limit as string) || 10;

	try {
		const result = await articleService.getArticlesByCategory(
			category,
			page,
			limit
		);

		res.json({
			success: true,
			data: result.articles,
			pagination: {
				currentPage: page,
				totalPages: result.totalPages,
				totalArticles: result.totalArticles,
			},
		});
	} catch (error) {
		console.error(`Error fetching articles for category ${category}:`, error);
		res.status(500).json({
			success: false,
			error: "Failed to fetch articles",
		});
	}
};

// Get articles by tag
export const getArticlesByTag = async (req: AuthRequest, res: Response) => {
	const { tag } = req.params;
	const page = parseInt(req.query.page as string) || 1;
	const limit = parseInt(req.query.limit as string) || 10;

	try {
		const result = await articleService.getArticlesByTag(tag, page, limit);

		res.json({
			success: true,
			data: result.articles,
			pagination: {
				currentPage: page,
				totalPages: result.totalPages,
				totalArticles: result.totalArticles,
			},
		});
	} catch (error) {
		console.error(`Error fetching articles for tag ${tag}:`, error);
		res.status(500).json({
			success: false,
			error: "Failed to fetch articles",
		});
	}
};

// Save article to user's favourites
export const saveArticleToFavourites = async (
	req: AuthRequest,
	res: Response
) => {
	const userId = req.user?._id || req.user?.id;
	const { id: articleId } = req.params;

	try {
		if (!userId) {
			return res.status(401).json({
				success: false,
				error: "Authentication required",
			});
		}

		await articleService.saveArticleToFavourites(userId, articleId);

		res.status(200).json({
			success: true,
			message: "Article saved to favourites",
		});
	} catch (error: any) {
		console.error(`Error saving article ${articleId} to favourites:`, error);

		if (error.message === "Article not found") {
			return res.status(404).json({
				success: false,
				error: "Article not found",
			});
		}

		if (error.message === "Article already in favourites") {
			return res.status(400).json({
				success: false,
				error: "Article already saved to favourites",
			});
		}

		res.status(500).json({
			success: false,
			error: "Failed to save article",
		});
	}
};

// Remove article from user's favourites
export const removeArticleFromFavourites = async (
	req: AuthRequest,
	res: Response
) => {
	const userId = req.user?._id || req.user?.id;
	const { id: articleId } = req.params;

	try {
		if (!userId) {
			return res.status(401).json({
				success: false,
				error: "Authentication required",
			});
		}

		await articleService.removeArticleFromFavourites(userId, articleId);

		res.status(200).json({
			success: true,
			message: "Article removed from favourites",
		});
	} catch (error: any) {
		console.error(
			`Error removing article ${articleId} from favourites:`,
			error
		);
		res.status(500).json({
			success: false,
			error: "Failed to remove article",
		});
	}
};

// Get user's favourite articles
export const getFavouriteArticles = async (req: AuthRequest, res: Response) => {
	const userId = req.user?._id || req.user?.id;
	const page = parseInt(req.query.page as string) || 1;
	const limit = parseInt(req.query.limit as string) || 10;

	try {
		if (!userId) {
			return res.status(401).json({
				success: false,
				error: "Authentication required",
			});
		}

		const result = await articleService.getFavouriteArticles(
			userId,
			page,
			limit
		);

		res.json({
			success: true,
			data: result.articles,
			pagination: {
				currentPage: page,
				totalPages: result.totalPages,
				totalArticles: result.totalArticles,
			},
		});
	} catch (error) {
		console.error(
			`Error fetching favourite articles for user ${userId}:`,
			error
		);
		res.status(500).json({
			success: false,
			error: "Failed to fetch favourite articles",
		});
	}
};

// Track article view (analytics)
export const incrementArticleView = async (req: AuthRequest, res: Response) => {
	const { id: articleId } = req.params;
	const userId = req.user?._id || req.user?.id; // Optional - tracks anonymous views too

	try {
		await articleService.incrementArticleView(articleId, userId);

		res.status(200).json({
			success: true,
			message: "View tracked",
		});
	} catch (error) {
		console.error(`Error tracking view for article ${articleId}:`, error);
		// Don't fail the request if analytics fail
		res.status(200).json({
			success: true,
			message: "View tracking failed but request completed",
		});
	}
};
