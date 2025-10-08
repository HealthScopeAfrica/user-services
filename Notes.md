# HealthScope Article API - Implementation Guide

## 🚀 Migration Steps

### 1. Update Article Model (article.model.ts)

**Current State:** Basic model with title, content, tags, author
**New State:** Enhanced with engagement metrics, multilingual support, and publishing workflow

```bash
# Before making changes, backup your existing articles
mongodump --db=healthscope --collection=articles
```

**Migration Script:**

```javascript
// scripts/migrate-articles.js
const Article = require('../models/article.model');

async function migrateArticles() {
  const articles = await Article.find({});

  for (const article of articles) {
    article.status = article.status || 'published';
    article.language = article.language || 'en';
    article.views = article.views || 0;
    article.likes = article.likes || 0;
    article.shares = article.shares || 0;
    article.reportCount = article.reportCount || 0;
    article.category = article.category || 'General Health';

    // Calculate read time
    const wordCount = article.content.split(/\s+/).length;
    article.readTime = Math.ceil(wordCount / 200);

    await article.save();
  }

  console.log('Migration complete!');
}

migrateArticles();
```

### 2. Update ReaderProfile Model

Add these fields to `reader-profile.model.ts`:

```typescript
interface IReaderProfile {
  // ... existing fields
  favourites: mongoose.Types.ObjectId[]; // Array of article IDs
  readingHistory: mongoose.Types.ObjectId[]; // Track read articles
  interests: string[]; // User interests for recommendations
  lastActive: Date;
}
```

### 3. Update Auth Middleware

✅ **Already done!** Just add the `optionalAuth` function to your existing `auth.middleware.ts`

### 4. Replace Controllers & Routes

**Steps:**

1. Backup your current files
2. Replace `articles.controller.ts` with the enhanced version
3. Replace `articles.route.ts` with the enhanced version
4. Replace `article.service.ts` with the enhanced version

### 5. Update Environment Variables

```env
JWT_SECRET=your-actual-secret-key-here
NODE_ENV=development
```

---

## 📊 API Endpoints Reference

### Public Endpoints (No Auth Required)

| Method | Endpoint | Description | Query Params |
|--------|----------|-------------|--------------|
| GET | `/api/articles` | Get all articles | `page`, `limit`, `category`, `tags`, `sortBy`, `order` |
| GET | `/api/articles/search` | Search articles | `q`, `page`, `limit` |
| GET | `/api/articles/trending` | Get trending articles | `limit`, `timeframe` |
| GET | `/api/articles/category/:category` | Filter by category | `page`, `limit` |
| GET | `/api/articles/tag/:tag` | Filter by tag | `page`, `limit` |
| GET | `/api/articles/:id` | Get single article | - |

### Protected Endpoints (Auth Required)

| Method | Endpoint | Description | Body/Params |
|--------|----------|-------------|-------------|
| GET | `/api/articles/recommended` | Get personalized recommendations | `limit` (query) |
| GET | `/api/articles/favourites` | Get saved articles | `page`, `limit` |
| POST | `/api/articles/:id/favourite` | Save to favourites | - |
| DELETE | `/api/articles/:id/favourite` | Remove from favourites | - |
| POST | `/api/articles/:id/view` | Track article view | - |

---

## 🧪 Testing the API

### 1. Get All Articles (Paginated)

```bash
curl http://localhost:3000/api/articles?page=1&limit=10&category=Mental%20Health
```

**Response:**

```json
{
  "success": true,
  "data": [...],
  "pagination": {
    "currentPage": 1,
    "totalPages": 5,
    "totalArticles": 48,
    "hasNext": true,
    "hasPrev": false
  }
}
```

### 2. Search Articles

```bash
curl http://localhost:3000/api/articles/search?q=malaria&page=1&limit=10
```

### 3. Get Trending Articles

```bash
curl http://localhost:3000/api/articles/trending?limit=10&timeframe=week
```

### 4. Save to Favourites (Authenticated)

```bash
curl -X POST http://localhost:3000/api/articles/6507f1f77bcf86cd99439011/favourite \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 5. Get Recommendations (Authenticated)

```bash
curl http://localhost:3000/api/articles/recommended?limit=10 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

---

## 🎯 Frontend Integration Examples

### React Hook for Articles

```typescript
// hooks/useArticles.ts
import { useState, useEffect } from 'react';

interface Article {
  _id: string;
  title: string;
  summary: string;
  featuredImage?: string;
  category: string;
  readTime: number;
  views: number;
  author: {
    name: string;
    profilePicture?: string;
  };
}

export const useArticles = (page: number = 1, category?: string) => {
  const [articles, setArticles] = useState<Article[]>([]);
  const [loading, setLoading] = useState(true);
  const [pagination, setPagination] = useState<any>(null);

  useEffect(() => {
    const fetchArticles = async () => {
      setLoading(true);
      const params = new URLSearchParams({
        page: page.toString(),
        limit: '10',
        ...(category && { category })
      });

      const response = await fetch(`/api/articles?${params}`);
      const data = await response.json();

      if (data.success) {
        setArticles(data.data);
        setPagination(data.pagination);
      }
      setLoading(false);
    };

    fetchArticles();
  }, [page, category]);

  return { articles, loading, pagination };
};
```

### Search Component

```typescript
// components/ArticleSearch.tsx
import { useState } from 'react';

export const ArticleSearch = () => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    const response = await fetch(`/api/articles/search?q=${query}`);
    const data = await response.json();
    if (data.success) setResults(data.data);
  };

  return (
    <form onSubmit={handleSearch}>
      <input
        type="text"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search health topics..."
      />
      <button type="submit">Search</button>

      {results.map(article => (
        <ArticleCard key={article._id} article={article} />
      ))}
    </form>
  );
};
```

---

## 🔒 Security Considerations

### 1. Rate Limiting

```typescript
// Add to your main app.ts or articles.route.ts
import rateLimit from 'express-rate-limit';

const articleLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  message: 'Too many requests, please try again later.'
});

router.use('/api/articles', articleLimiter);
```

### 2. Input Validation

```typescript
// Install: npm install express-validator
import { query, param } from 'express-validator';

const validateSearch = [
  query('q').trim().isLength({ min: 2, max: 100 })
    .withMessage('Search query must be 2-100 characters'),
  query('page').optional().isInt({ min: 1 })
    .withMessage('Page must be a positive integer')
];

router.get('/search', validateSearch, searchArticles);
```

### 3. Content Sanitization

```typescript
// Install: npm install sanitize-html
import sanitizeHtml from 'sanitize-html';

// In article service before saving
const sanitizedContent = sanitizeHtml(content, {
  allowedTags: ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li'],
  allowedAttributes: {
    'a': ['href']
  }
});
```

---

## 📈 Performance Optimization

### 1. Database Indexes (Already included in model)

- Status + CreatedAt compound index
- Category + Status compound index
- Text search index on title, summary, content
- Views index for trending queries

### 2. Caching Strategy (Redis)

```typescript
// services/cache.service.ts
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

export const cacheArticles = async (key: string, data: any, ttl: number = 300) => {
  await redis.setex(key, ttl, JSON.stringify(data));
};

export const getCachedArticles = async (key: string) => {
  const cached = await redis.get(key);
  return cached ? JSON.parse(cached) : null;
};
```

**Usage in Service:**

```typescript
getTrendingArticles = async (limit: number, timeframe: string) => {
  const cacheKey = `trending:${timeframe}:${limit}`;
  const cached = await getCachedArticles(cacheKey);
  if (cached) return cached;

  const articles = await Article.find(/* ... */);
  await cacheArticles(cacheKey, articles, 600); // Cache for 10 min
  return articles;
};
```

---

## 🐛 Troubleshooting

### Issue: Routes not working

**Solution:** Check route order in `articles.route.ts`. Specific routes must come before dynamic `:id` routes.

### Issue: User ID not found in req.user

**Solution:** The code handles both `req.user._id` and `req.user.id`. Check your JWT payload structure.

### Issue: Articles not appearing in search

**Solution:** Ensure text indexes are created. Run:

```javascript
db.articles.createIndex({
  title: "text",
  summary: "text",
  content: "text",
  tags: "text"
});
```

### Issue: Favourites not saving

**Solution:** Verify `ReaderProfileModel` has the `favourites` field as an array of ObjectIds.

---

## 🎨 Next Features to Consider

1. **Comments & Discussions** - Allow readers to comment on articles
2. **Bookmarks with Notes** - Let users add personal notes to saved articles
3. **Reading Progress** - Track how much of an article user has read
4. **Article Series** - Group related articles into series/courses
5. **Multi-language Toggle** - Switch between language versions
6. **Offline Access** - Progressive Web App with offline reading
7. **Audio Player** - Built-in player for audio versions
8. **Social Sharing** - Share to WhatsApp, Twitter, Facebook with custom cards
9. **Article Analytics Dashboard** - For contributors to see their article performance
10. **Related Articles ML** - Use TensorFlow.js for better recommendations

---

## 📞 Support & Documentation

- **API Docs:** Consider using Swagger/OpenAPI for auto-generated docs
- **Monitoring:** Integrate Sentry for error tracking
- **Analytics:** Track user behavior with Mixpanel or PostHog

**Questions?** Open an issue or reach out to the team! 🚀
