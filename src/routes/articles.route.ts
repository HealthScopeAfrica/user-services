// Enhanced article routes for reader-facing application
import { Router } from "express";
import { authenticate, optionalAuth } from "../middlewares/auth.middleware";
import {
	getArticles,
	getArticleById,
	getRecommendedArticles,
	saveArticleToFavourites,
	removeArticleFromFavourites,
	getTrendingArticles,
	searchArticles,
	getArticlesByCategory,
	getArticlesByTag,
	incrementArticleView,
	getFavouriteArticles,
} from "../controllers/articles.controller";

const router = Router();

// Public routes - accessible without authentication
router.get("/", getArticles); // Get paginated articles with filters
router.get("/search", searchArticles); // Search articles by query
router.get("/trending", getTrendingArticles); // Get trending articles
router.get("/category/:category", getArticlesByCategory); // Filter by category
router.get("/tag/:tag", getArticlesByTag); // Filter by tag

// Protected routes - require authentication
router.get("/recommended", authenticate, getRecommendedArticles); // Personalized recommendations
router.get("/favourites", authenticate, getFavouriteArticles); // User's saved articles

// Article-specific routes (order matters - specific before dynamic)
router.post("/:id/favourite", authenticate, saveArticleToFavourites); // Save to favourites
router.delete("/:id/favourite", authenticate, removeArticleFromFavourites); // Remove from favourites
router.post("/:id/view", optionalAuth, incrementArticleView); // Track view (with optional user tracking)
router.get("/:id", optionalAuth, getArticleById); // Get single article (track if authenticated)

export default router;
