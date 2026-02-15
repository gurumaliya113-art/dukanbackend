const express = require("express");
const cors = require("cors");
const multer = require("multer");
const crypto = require("crypto");
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const { supabasePublic, supabaseAdmin } = require("./supabaseClients");

const app = express();

app.use(
    cors({
        origin: true,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);
app.use(express.json());

const getBearerToken = (req) => {
    const header = req.headers.authorization || req.headers.Authorization || "";
    const value = Array.isArray(header) ? header[0] : String(header);
    if (value.toLowerCase().startsWith("bearer ")) return value.slice(7).trim();
    return "";
};

const requireAdmin = async (req, res, next) => {
    try {
        if (!supabaseAdmin) {
            return res.status(500).json({
                error: "Server not configured for admin writes",
                hint:
                    "Set SUPABASE_SERVICE_ROLE_KEY in backend/.env and restart backend.",
            });
        }

        const token = getBearerToken(req);
        if (!token) {
            return res.status(401).json({ error: "Missing Authorization bearer token" });
        }

        const { data: userData, error: userError } = await supabasePublic.auth.getUser(token);
        if (userError || !userData?.user) {
            return res.status(401).json({ error: "Invalid or expired token" });
        }

        const user = userData.user;
        const { data: adminRow, error: adminError } = await supabaseAdmin
            .from("admin_users")
            .select("user_id,email")
            .eq("user_id", user.id)
            .maybeSingle();

        if (adminError) {
            return res.status(500).json({
                error: adminError.message || "Admin lookup failed",
                hint: "Create the 'admin_users' table in Supabase (SQL provided in setup notes).",
            });
        }

        if (!adminRow) {
            return res.status(403).json({ error: "Not an admin" });
        }

        req.admin = { id: user.id, email: adminRow.email || user.email || null };
        return next();
    } catch (e) {
        return res.status(500).json({ error: e?.message || "Admin auth failed" });
    }
};

const requireCustomer = async (req, res, next) => {
    try {
        const token = getBearerToken(req);
        if (!token) return res.status(401).json({ error: "Missing Authorization bearer token" });

        const { data: userData, error: userError } = await supabasePublic.auth.getUser(token);
        if (userError || !userData?.user) {
            return res.status(401).json({ error: "Invalid or expired token" });
        }

        req.customer = userData.user;
        return next();
    } catch (e) {
        return res.status(500).json({ error: e?.message || "Customer auth failed" });
    }
};

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
});

const parseNumberOrNull = (value) => {
    if (value === undefined || value === null || value === "") return null;
    const n = typeof value === "string" ? Number(value) : Number(value);
    if (Number.isNaN(n)) return null;
    return n;
};

const parseIntOrNull = (value) => {
    const n = parseNumberOrNull(value);
    if (n === null) return null;
    if (!Number.isFinite(n)) return null;
    return Math.trunc(n);
};

const parseDateTimeOrNull = (value) => {
    if (value === undefined || value === null || value === "") return null;
    try {
        const d = new Date(value);
        if (Number.isNaN(d.getTime())) return null;
        return d.toISOString();
    } catch {
        return null;
    }
};

const PRODUCT_SIZE_OPTIONS = [
    "0-1 year",
    "1-2 year",
    "2-4 year",
    "S",
    "M",
    "L",
    "XL",
    "XXL",
    "XXXL",
];

const parseProductSizesOrNull = (value) => {
    if (value === undefined || value === null || value === "") return null;

    let rawList = [];
    if (Array.isArray(value)) {
        rawList = value;
    } else {
        const s = String(value);
        const trimmed = s.trim();
        if (!trimmed) return null;

        // FormData typically sends JSON string like: ["S","M"]
        if ((trimmed.startsWith("[") && trimmed.endsWith("]")) || (trimmed.startsWith("\"") && trimmed.endsWith("\""))) {
            try {
                const parsed = JSON.parse(trimmed);
                if (Array.isArray(parsed)) rawList = parsed;
                else if (typeof parsed === "string") rawList = parsed.split(",");
            } catch {
                rawList = trimmed.split(",");
            }
        } else {
            rawList = trimmed.split(",");
        }
    }

    const allowed = new Map(PRODUCT_SIZE_OPTIONS.map((x) => [String(x).toLowerCase(), x]));
    const picked = [];
    const seen = new Set();

    for (const item of rawList) {
        const normalized = String(item || "").trim();
        if (!normalized) continue;
        const canon = allowed.get(normalized.toLowerCase());
        if (!canon) continue;
        if (seen.has(canon)) continue;
        seen.add(canon);
        picked.push(canon);
    }

    if (!picked.length) return null;

    // Keep a stable order.
    const weight = new Map(PRODUCT_SIZE_OPTIONS.map((x, i) => [x, i]));
    picked.sort((a, b) => (weight.get(a) ?? 999) - (weight.get(b) ?? 999));
    return picked;
};

const isMissingColumnError = (err) => {
    const msg = String(err?.message || "").toLowerCase();
    // Postgres (SQL) style
    if (msg.includes("column") && msg.includes("does not exist")) return true;
    // PostgREST / Supabase schema cache style
    if (msg.includes("schema cache") && msg.includes("could not find") && msg.includes("column")) return true;
    if (msg.includes("could not find") && msg.includes("column") && msg.includes("schema cache")) return true;
    return false;
};

const normalizeCategory = (value) => {
    const raw = value === undefined || value === null ? "" : String(value);
    const v = raw.trim().toLowerCase();
    if (!v) return "new";
    if (v === "new" || v === "new-arrivals" || v === "new arrivals" || v === "arrivals") return "new";
    if (v === "men" || v === "man" || v === "mens" || v === "men's") return "men";
    if (v === "women" || v === "woman" || v === "womens" || v === "women's") return "women";
    if (v === "kids" || v === "kid" || v === "children" || v === "child") return "kids";
    return "new";
};

const insertWithFallback = async (table, row, fallbackRow) => {
    let result = await supabaseAdmin.from(table).insert([row]).select("*").single();
        result.usedFallback = false;
        if (result.error && isMissingColumnError(result.error) && fallbackRow) {
            const fallback = await supabaseAdmin.from(table).insert([fallbackRow]).select("*").single();
            fallback.usedFallback = true;
            return fallback;
        }
        return result;
};

const updateWithFallback = async (table, update, whereEq, fallbackUpdate) => {
    let q = supabaseAdmin.from(table).update(update);
    Object.entries(whereEq || {}).forEach(([k, v]) => {
        q = q.eq(k, v);
    });
    let result = await q.select("*").maybeSingle();

    result.usedFallback = false;
    if (result.error && isMissingColumnError(result.error) && fallbackUpdate) {
        let q2 = supabaseAdmin.from(table).update(fallbackUpdate);
        Object.entries(whereEq || {}).forEach(([k, v]) => {
            q2 = q2.eq(k, v);
        });
        result = await q2.select("*").maybeSingle();

        result.usedFallback = true;
    }

    return result;
};

const attachTrackingUpdates = async (orders) => {
    if (!supabaseAdmin) return orders;
    if (!Array.isArray(orders) || orders.length === 0) return orders;

    const ids = orders.map((o) => o?.id).filter(Boolean);
    if (ids.length === 0) return orders;

    try {
        const { data: updates, error } = await supabaseAdmin
            .from("order_tracking_updates")
            .select("id,order_id,location,note,created_at")
            .in("order_id", ids)
            .order("created_at", { ascending: false });

        if (error) {
            // If table/columns not present yet, do not fail main response.
            return orders;
        }

        const grouped = new Map();
        (updates || []).forEach((u) => {
            const key = u.order_id;
            if (!grouped.has(key)) grouped.set(key, []);
            grouped.get(key).push(u);
        });

        return orders.map((o) => ({
            ...o,
            tracking_received: grouped.get(o.id) || [],
        }));
    } catch {
        return orders;
    }
};

const maybeUploadImages = (req, res, next) => {
    const contentType = req.headers["content-type"] || "";
    if (contentType.startsWith("multipart/form-data")) {
        return upload.array("images", 4)(req, res, next);
    }
    return next();
};

const getBucketName = () => process.env.SUPABASE_PRODUCTS_BUCKET || "product-images";

const isNotFoundBucketError = (err) => {
    const msg = (err?.message || "").toLowerCase();
    const code = err?.statusCode || err?.status;
    return code === 404 || (msg.includes("bucket") && msg.includes("not found"));
};

const ensureBucketExists = async (bucket) => {
    // Requires a key with Storage admin privileges (service role).
    try {
        if (!supabaseAdmin) {
            return { ok: false, error: { message: "Missing SUPABASE_SERVICE_ROLE_KEY" } };
        }

        if (typeof supabaseAdmin.storage?.getBucket === "function") {
            const { data, error } = await supabaseAdmin.storage.getBucket(bucket);
            if (data && !error) {
                // If bucket exists but is private, make it public so the stored public URLs actually load.
                if (data.public === false && typeof supabaseAdmin.storage?.updateBucket === "function") {
                    const { error: updateError } = await supabaseAdmin.storage.updateBucket(bucket, { public: true });
                    if (updateError) return { ok: false, error: updateError };
                    return { ok: true, created: false, updated: true };
                }
                return { ok: true, created: false };
            }
            if (error && isNotFoundBucketError(error) && typeof supabaseAdmin.storage?.createBucket === "function") {
                const { error: createError } = await supabaseAdmin.storage.createBucket(bucket, { public: true });
                if (!createError) return { ok: true, created: true };
                return { ok: false, error: createError };
            }
            if (error) return { ok: false, error };
        }

        if (typeof supabaseAdmin.storage?.listBuckets === "function") {
            const { data, error } = await supabaseAdmin.storage.listBuckets();
            if (error) return { ok: false, error };
            const exists = Array.isArray(data) && data.some((b) => b?.name === bucket);
            if (exists) return { ok: true, created: false };
            if (typeof supabaseAdmin.storage?.createBucket === "function") {
                const { error: createError } = await supabaseAdmin.storage.createBucket(bucket, { public: true });
                if (!createError) return { ok: true, created: true };
                return { ok: false, error: createError };
            }
        }

        return { ok: false, error: { message: "Storage API not available" } };
    } catch (e) {
        return { ok: false, error: e };
    }
};

// TEST ROUTE
app.get("/", (req, res) => {
    res.send("Backend chal raha hai 🔥");
});

// Quick diagnostic: helps confirm which backend code is running
app.get("/__build", (req, res) => {
    return res.json({
        ok: true,
        name: "dukan-backend",
        multiRegionPricing: true,
        expects: ["price_inr", "price_usd"],
        time: new Date().toISOString(),
    });
});

// 👉 ADMIN: who am I (protected)
app.get("/admin/me", requireAdmin, (req, res) => {
    return res.json({ ok: true, admin: req.admin });
});

// 👉 ADMIN: create a new admin account (invite-code protected)
app.post("/admin/create", async (req, res) => {
    const { email, password, inviteCode } = req.body || {};

    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint:
                "Set SUPABASE_SERVICE_ROLE_KEY in backend/.env and restart backend.",
        });
    }

    const serverInvite = process.env.ADMIN_INVITE_CODE || "";
    if (!serverInvite) {
        return res.status(500).json({
            error: "ADMIN_INVITE_CODE not configured",
            hint: "Set ADMIN_INVITE_CODE in backend/.env and restart backend.",
        });
    }

    if (!inviteCode || String(inviteCode) !== String(serverInvite)) {
        return res.status(403).json({ error: "Invalid invite code" });
    }

    if (!email || !String(email).includes("@")) {
        return res.status(400).json({ error: "Valid email required" });
    }

    if (!password || String(password).length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const { data: created, error: createError } = await supabaseAdmin.auth.admin.createUser({
        email: normalizedEmail,
        password: String(password),
        email_confirm: true,
    });

    // If user already exists, do not fail. Just grant admin to that existing user.
    let userId = created?.user?.id || null;
    let userEmail = created?.user?.email || normalizedEmail;
    let existed = false;

    if (createError || !created?.user) {
        const msg = String(createError?.message || "");
        const looksLikeExists = /already\s+been\s+registered|already\s+registered|user\s+already\s+registered|email\s+already\s+exists|duplicate/i.test(
            msg.toLowerCase()
        );

        if (!looksLikeExists) {
            return res.status(400).json({ error: createError?.message || "Failed to create admin user" });
        }

        const { data: existing, error: existingError } = await supabaseAdmin.auth.admin.getUserByEmail(
            normalizedEmail
        );

        if (existingError || !existing?.user) {
            return res.status(400).json({
                error: existingError?.message || msg || "User exists but lookup failed",
                hint: "Try logging in on Admin Panel (Login tab) or check Supabase Auth users.",
            });
        }

        existed = true;
        userId = existing.user.id;
        userEmail = existing.user.email || normalizedEmail;
    }

    const { error: insertError } = await supabaseAdmin
        .from("admin_users")
        .upsert([{ user_id: userId, email: userEmail }], { onConflict: "user_id" });

    if (insertError) {
        return res.status(400).json({ error: insertError.message || "Failed to mark user as admin" });
    }

    return res.status(existed ? 200 : 201).json({ ok: true, userId, email: userEmail, existed });
});

// 👉 PRODUCTS ROUTE (YE ZAROORI HAI)
app.get("/products", async (req, res) => {
    const category = normalizeCategory(req.query?.category);

    let query = supabasePublic.from("products").select("*");
    // When category=NEW, include legacy rows where category is NULL (pre-migration)
    if (req.query?.category !== undefined) {
        if (category === "new") {
            query = query.or("category.eq.new,category.is.null");
        } else {
            query = query.eq("category", category);
        }
    }

    let { data, error } = await query;
    if (error && isMissingColumnError(error)) {
        // DB not migrated yet - return all products
        const fallback = await supabasePublic.from("products").select("*");
        data = fallback.data;
        error = fallback.error;
    }

    if (error) {
        return res.status(400).json(error);
    }

    res.json(data);
});

// 👉 SINGLE PRODUCT (DETAIL PAGE)
app.get("/products/:id", async (req, res) => {
    const id = Number(req.params.id);
    if (Number.isNaN(id)) {
        return res.status(400).json({ error: "Invalid product id" });
    }

    const { data, error } = await supabasePublic
        .from("products")
        .select("*")
        .eq("id", id)
        .maybeSingle();

    if (error) {
        return res.status(400).json(error);
    }

    if (!data) {
        return res.status(404).json({ error: "Product not found" });
    }

    res.json(data);
});

// 👉 ADD PRODUCT (ADMIN)
app.post("/products", requireAdmin, maybeUploadImages, async (req, res) => {
    const { name, description } = req.body || {};
    const category = normalizeCategory(req.body?.category);
    const priceInrRaw = req.body?.price_inr ?? req.body?.priceInr ?? req.body?.price;
    const priceUsdRaw = req.body?.price_usd ?? req.body?.priceUsd;
    const mrpInrRaw = req.body?.mrp_inr ?? req.body?.mrpInr ?? req.body?.mrp;
    const mrpUsdRaw = req.body?.mrp_usd ?? req.body?.mrpUsd;
    const costInrRaw = req.body?.cost_inr ?? req.body?.costInr;
    const costUsdRaw = req.body?.cost_usd ?? req.body?.costUsd;
    const sizesRaw = req.body?.sizes;
    const skuRaw = req.body?.sku;
    const barcodeRaw = req.body?.barcode;
    const quantityRaw = req.body?.quantity ?? req.body?.stock_quantity ?? req.body?.stock;

    try {
        const keys = Object.keys(req.body || {});
        console.log("[products:create] body keys:", keys, "files:", Array.isArray(req.files) ? req.files.length : 0);
    } catch {
        // ignore logging errors
    }

    // Inserts/uploads should use service role to avoid RLS blocking ("new row violates row-level security policy")
    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint:
                "Create backend/.env (see backend/.env.example) and set SUPABASE_SERVICE_ROLE_KEY from Supabase Settings -> API, then restart backend.",
        });
    }

    const parsedPriceInr = parseNumberOrNull(priceInrRaw);
    const parsedPriceUsd = parseNumberOrNull(priceUsdRaw);
    const parsedMrpInr = parseNumberOrNull(mrpInrRaw);
    const parsedMrpUsd = parseNumberOrNull(mrpUsdRaw);
    const parsedCostInr = parseNumberOrNull(costInrRaw);
    const parsedCostUsd = parseNumberOrNull(costUsdRaw);
    const parsedQuantity = quantityRaw !== undefined ? parseIntOrNull(quantityRaw) : null;

    if (!name || parsedPriceInr === null) {
        return res.status(400).json({
            error: "Missing required fields: name, price_inr (or legacy price)",
            received: Object.keys(req.body || {}),
        });
    }

    if (quantityRaw !== undefined) {
        if (parsedQuantity === null) {
            return res.status(400).json({ error: "quantity must be an integer" });
        }
        if (parsedQuantity < 0) {
            return res.status(400).json({ error: "quantity cannot be negative" });
        }
    }

    let imageUrls = {
        image1: null,
        image2: null,
        image3: null,
        image4: null,
    };

    // If request is multipart, upload images to Supabase Storage
    if (Array.isArray(req.files) && req.files.length > 0) {
        const bucket = getBucketName();
        const allowed = new Set(["image/jpeg", "image/png", "image/webp"]);

        const bucketCheck = await ensureBucketExists(bucket);
        if (!bucketCheck.ok) {
            const message = bucketCheck?.error?.message || "Bucket not found";
            return res.status(500).json({
                error: message,
                hint:
                    `Create a Supabase Storage bucket named '${bucket}' (make it Public for beginner setup), or set SUPABASE_SERVICE_ROLE_KEY in backend/.env so the server can create it automatically.`,
            });
        }

        for (let i = 0; i < Math.min(req.files.length, 4); i++) {
            const file = req.files[i];
            if (!allowed.has(file.mimetype)) {
                return res.status(400).json({
                    error: "Only JPG/PNG/WEBP images are allowed",
                });
            }

            const ext = file.mimetype === "image/png" ? "png" : file.mimetype === "image/webp" ? "webp" : "jpg";
            const objectPath = `products/${Date.now()}-${crypto.randomUUID()}.${ext}`;

            const { error: uploadError } = await supabaseAdmin
                .storage
                .from(bucket)
                .upload(objectPath, file.buffer, {
                    contentType: file.mimetype,
                    upsert: false,
                });

            if (uploadError) {
                // One more attempt: bucket might have been deleted/renamed.
                if (isNotFoundBucketError(uploadError)) {
                    const retryCheck = await ensureBucketExists(bucket);
                    if (retryCheck.ok) {
                        const { error: retryError } = await supabaseAdmin
                            .storage
                            .from(bucket)
                            .upload(objectPath, file.buffer, {
                                contentType: file.mimetype,
                                upsert: false,
                            });
                        if (!retryError) {
                            const { data: publicData } = supabaseAdmin.storage.from(bucket).getPublicUrl(objectPath);
                            const publicUrl = publicData?.publicUrl || null;

                            if (i === 0) imageUrls.image1 = publicUrl;
                            if (i === 1) imageUrls.image2 = publicUrl;
                            if (i === 2) imageUrls.image3 = publicUrl;
                            if (i === 3) imageUrls.image4 = publicUrl;
                            continue;
                        }
                    }
                }
                return res.status(500).json({
                    error: uploadError.message || "Image upload failed",
                    hint: `Make sure Supabase Storage bucket '${bucket}' exists and is public (or policies allow uploads).`,
                });
            }

            const { data: publicData } = supabaseAdmin.storage.from(bucket).getPublicUrl(objectPath);
            const publicUrl = publicData?.publicUrl || null;

            if (i === 0) imageUrls.image1 = publicUrl;
            if (i === 1) imageUrls.image2 = publicUrl;
            if (i === 2) imageUrls.image3 = publicUrl;
            if (i === 3) imageUrls.image4 = publicUrl;
        }
    } else {
        // JSON mode (legacy): accept image URLs directly
        const { image1, image2, image3, image4 } = req.body || {};
        imageUrls = {
            image1: image1 || null,
            image2: image2 || null,
            image3: image3 || null,
            image4: image4 || null,
        };
    }

    const row = {
        name,
        category,
        // Keep legacy 'price' for backward compatibility
        price: parsedPriceInr,
        price_inr: parsedPriceInr,
        price_usd: parsedPriceUsd,
        mrp_inr: parsedMrpInr,
        mrp_usd: parsedMrpUsd,
        cost_inr: costInrRaw !== undefined ? parsedCostInr : null,
        cost_usd: costUsdRaw !== undefined ? parsedCostUsd : null,
        description: description || null,
        sizes: parseProductSizesOrNull(sizesRaw),
        sku: skuRaw !== undefined && String(skuRaw).trim() ? String(skuRaw).trim() : null,
        barcode: barcodeRaw !== undefined && String(barcodeRaw).trim() ? String(barcodeRaw).trim() : null,
        quantity: quantityRaw !== undefined ? parsedQuantity : null,
        ...imageUrls,
    };

    const fallbackRow = {
        name,
        price: parsedPriceInr,
        description: description || null,
        ...imageUrls,
    };

    const result = await insertWithFallback("products", row, fallbackRow);
    const { data, error } = result;
    if (error) return res.status(400).json(error);

    const requestedSizes = sizesRaw !== undefined && sizesRaw !== null && String(sizesRaw).trim() !== "";
    if (requestedSizes && result.usedFallback) {
        return res.status(201).json({
            ...data,
            warning: "Product saved, but sizes were NOT saved (DB missing products.sizes column). Run supabase-products-sizes.sql in Supabase SQL editor.",
        });
    }

    const requestedInventory =
        (skuRaw !== undefined && String(skuRaw).trim() !== "") ||
        (barcodeRaw !== undefined && String(barcodeRaw).trim() !== "") ||
        quantityRaw !== undefined;
    if (requestedInventory && result.usedFallback) {
        return res.status(201).json({
            ...data,
            warning:
                "Product saved, but inventory fields (sku/barcode/quantity) were NOT saved (DB missing columns). Run supabase-products-inventory.sql in Supabase SQL editor.",
        });
    }

    const requestedCost = (costInrRaw !== undefined && String(costInrRaw).trim() !== "") || (costUsdRaw !== undefined && String(costUsdRaw).trim() !== "");
    if (requestedCost && result.usedFallback) {
        return res.status(201).json({
            ...data,
            warning:
                "Product saved, but cost fields (cost_inr/cost_usd) were NOT saved (DB missing columns). Run supabase-products-cost.sql in Supabase SQL editor.",
        });
    }

    return res.status(201).json(data);
});

// 👉 UPDATE PRODUCT (ADMIN)
app.put("/products/:id", requireAdmin, maybeUploadImages, async (req, res) => {
    const id = Number(req.params.id);
    if (Number.isNaN(id)) {
        return res.status(400).json({ error: "Invalid product id" });
    }

    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint:
                "Create backend/.env (see backend/.env.example) and set SUPABASE_SERVICE_ROLE_KEY from Supabase Settings -> API, then restart backend.",
        });
    }

    const { data: existing, error: existingError } = await supabaseAdmin
        .from("products")
        .select("*")
        .eq("id", id)
        .maybeSingle();

    if (existingError) {
        return res.status(400).json(existingError);
    }

    if (!existing) {
        return res.status(404).json({ error: "Product not found" });
    }

    const update = {};

    const removeFlags = {
        image1: String(req.body?.removeImage1 || "") === "1",
        image2: String(req.body?.removeImage2 || "") === "1",
        image3: String(req.body?.removeImage3 || "") === "1",
        image4: String(req.body?.removeImage4 || "") === "1",
    };

    if (removeFlags.image1) update.image1 = null;
    if (removeFlags.image2) update.image2 = null;
    if (removeFlags.image3) update.image3 = null;
    if (removeFlags.image4) update.image4 = null;

    const { name, description } = req.body || {};
    const categoryRaw = req.body?.category;
    const priceInrRaw = req.body?.price_inr ?? req.body?.priceInr;
    const priceUsdRaw = req.body?.price_usd ?? req.body?.priceUsd;
    const mrpInrRaw = req.body?.mrp_inr ?? req.body?.mrpInr;
    const mrpUsdRaw = req.body?.mrp_usd ?? req.body?.mrpUsd;
    const costInrRaw = req.body?.cost_inr ?? req.body?.costInr;
    const costUsdRaw = req.body?.cost_usd ?? req.body?.costUsd;
    const legacyPriceRaw = req.body?.price;
    const sizesRaw = req.body?.sizes;
    const skuRaw = req.body?.sku;
    const barcodeRaw = req.body?.barcode;
    const quantityRaw = req.body?.quantity ?? req.body?.stock_quantity ?? req.body?.stock;

    if (categoryRaw !== undefined) {
        update.category = normalizeCategory(categoryRaw);
    }
    if (name !== undefined) {
        const trimmed = String(name).trim();
        if (!trimmed) return res.status(400).json({ error: "name cannot be empty" });
        update.name = trimmed;
    }

    const parsedPriceInr = priceInrRaw !== undefined ? parseNumberOrNull(priceInrRaw) : null;
    const parsedPriceUsd = priceUsdRaw !== undefined ? parseNumberOrNull(priceUsdRaw) : null;
    const parsedMrpInr = mrpInrRaw !== undefined ? parseNumberOrNull(mrpInrRaw) : null;
    const parsedMrpUsd = mrpUsdRaw !== undefined ? parseNumberOrNull(mrpUsdRaw) : null;
    const parsedCostInr = costInrRaw !== undefined ? parseNumberOrNull(costInrRaw) : null;
    const parsedCostUsd = costUsdRaw !== undefined ? parseNumberOrNull(costUsdRaw) : null;
    const parsedLegacyPrice = legacyPriceRaw !== undefined ? parseNumberOrNull(legacyPriceRaw) : null;

    if (priceInrRaw !== undefined) {
        if (parsedPriceInr === null) return res.status(400).json({ error: "price_inr must be a number" });
        update.price = parsedPriceInr;
        update.price_inr = parsedPriceInr;
    } else if (legacyPriceRaw !== undefined) {
        if (parsedLegacyPrice === null) return res.status(400).json({ error: "price must be a number" });
        update.price = parsedLegacyPrice;
        update.price_inr = parsedLegacyPrice;
    }

    if (priceUsdRaw !== undefined) {
        if (parsedPriceUsd === null) return res.status(400).json({ error: "price_usd must be a number" });
        update.price_usd = parsedPriceUsd;
    }

    if (mrpInrRaw !== undefined) {
        update.mrp_inr = parsedMrpInr;
    }

    if (mrpUsdRaw !== undefined) {
        update.mrp_usd = parsedMrpUsd;
    }

    if (costInrRaw !== undefined) {
        update.cost_inr = parsedCostInr;
    }

    if (costUsdRaw !== undefined) {
        update.cost_usd = parsedCostUsd;
    }

    if (description !== undefined) {
        const trimmed = String(description).trim();
        update.description = trimmed ? trimmed : null;
    }

    if (sizesRaw !== undefined) {
        update.sizes = parseProductSizesOrNull(sizesRaw);
    }

    if (skuRaw !== undefined) {
        const trimmed = String(skuRaw || "").trim();
        update.sku = trimmed ? trimmed : null;
    }

    if (barcodeRaw !== undefined) {
        const trimmed = String(barcodeRaw || "").trim();
        update.barcode = trimmed ? trimmed : null;
    }

    if (quantityRaw !== undefined) {
        const parsed = parseIntOrNull(quantityRaw);
        if (parsed === null) return res.status(400).json({ error: "quantity must be an integer" });
        if (parsed < 0) return res.status(400).json({ error: "quantity cannot be negative" });
        update.quantity = parsed;
    }

    // If request is multipart and includes images, upload and replace image slots.
    if (Array.isArray(req.files) && req.files.length > 0) {
        const bucket = getBucketName();
        const allowed = new Set(["image/jpeg", "image/png", "image/webp"]);

        const bucketCheck = await ensureBucketExists(bucket);
        if (!bucketCheck.ok) {
            const message = bucketCheck?.error?.message || "Bucket not found";
            return res.status(500).json({
                error: message,
                hint:
                    `Create a Supabase Storage bucket named '${bucket}' (make it Public for beginner setup), or set SUPABASE_SERVICE_ROLE_KEY in backend/.env so the server can create it automatically.`,
            });
        }

        const nextImages = {
            image1: existing.image1 || null,
            image2: existing.image2 || null,
            image3: existing.image3 || null,
            image4: existing.image4 || null,
        };

        // Apply explicit removals before replacing images.
        if (removeFlags.image1) nextImages.image1 = null;
        if (removeFlags.image2) nextImages.image2 = null;
        if (removeFlags.image3) nextImages.image3 = null;
        if (removeFlags.image4) nextImages.image4 = null;

        for (let i = 0; i < Math.min(req.files.length, 4); i++) {
            const file = req.files[i];
            if (!allowed.has(file.mimetype)) {
                return res.status(400).json({
                    error: "Only JPG/PNG/WEBP images are allowed",
                });
            }

            const ext =
                file.mimetype === "image/png"
                    ? "png"
                    : file.mimetype === "image/webp"
                        ? "webp"
                        : "jpg";
            const objectPath = `products/${Date.now()}-${crypto.randomUUID()}.${ext}`;

            const { error: uploadError } = await supabaseAdmin
                .storage
                .from(bucket)
                .upload(objectPath, file.buffer, {
                    contentType: file.mimetype,
                    upsert: false,
                });

            if (uploadError) {
                return res.status(500).json({
                    error: uploadError.message || "Image upload failed",
                    hint: `Make sure Supabase Storage bucket '${bucket}' exists and is public (or policies allow uploads).`,
                });
            }

            const { data: publicData } = supabaseAdmin.storage.from(bucket).getPublicUrl(objectPath);
            const publicUrl = publicData?.publicUrl || null;

            if (i === 0) nextImages.image1 = publicUrl;
            if (i === 1) nextImages.image2 = publicUrl;
            if (i === 2) nextImages.image3 = publicUrl;
            if (i === 3) nextImages.image4 = publicUrl;
        }

        Object.assign(update, nextImages);
    } else {
        // JSON mode: accept image URLs directly (optional)
        const { image1, image2, image3, image4 } = req.body || {};
        if (image1 !== undefined) update.image1 = image1 ? String(image1) : null;
        if (image2 !== undefined) update.image2 = image2 ? String(image2) : null;
        if (image3 !== undefined) update.image3 = image3 ? String(image3) : null;
        if (image4 !== undefined) update.image4 = image4 ? String(image4) : null;
    }

    if (Object.keys(update).length === 0) {
        return res.status(400).json({ error: "No fields to update" });
    }

    const fallbackUpdate = { ...update };
    delete fallbackUpdate.price_inr;
    delete fallbackUpdate.price_usd;
    delete fallbackUpdate.mrp_inr;
    delete fallbackUpdate.mrp_usd;
    delete fallbackUpdate.cost_inr;
    delete fallbackUpdate.cost_usd;
    delete fallbackUpdate.sizes;
    delete fallbackUpdate.sku;
    delete fallbackUpdate.barcode;
    delete fallbackUpdate.quantity;

    const result = await updateWithFallback(
        "products",
        update,
        { id },
        fallbackUpdate
    );
    const { data: updated, error: updateError } = result;

    if (updateError) return res.status(400).json(updateError);

    const requestedSizes = sizesRaw !== undefined && sizesRaw !== null && String(sizesRaw).trim() !== "";
    if (requestedSizes && result.usedFallback) {
        return res.json({
            ...updated,
            warning: "Product updated, but sizes were NOT saved (DB missing products.sizes column). Run supabase-products-sizes.sql in Supabase SQL editor.",
        });
    }

    const requestedInventory = skuRaw !== undefined || barcodeRaw !== undefined || quantityRaw !== undefined;
    if (requestedInventory && result.usedFallback) {
        return res.json({
            ...updated,
            warning:
                "Product updated, but inventory fields (sku/barcode/quantity) were NOT saved (DB missing columns). Run supabase-products-inventory.sql in Supabase SQL editor.",
        });
    }

    const requestedCost = costInrRaw !== undefined || costUsdRaw !== undefined;
    if (requestedCost && result.usedFallback) {
        return res.json({
            ...updated,
            warning:
                "Product updated, but cost fields (cost_inr/cost_usd) were NOT saved (DB missing columns). Run supabase-products-cost.sql in Supabase SQL editor.",
        });
    }

    return res.json(updated);
});

// 👉 DELETE PRODUCT (ADMIN)
app.delete("/products/:id", requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (Number.isNaN(id)) {
        return res.status(400).json({ error: "Invalid product id" });
    }

    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint:
                "Create backend/.env (see backend/.env.example) and set SUPABASE_SERVICE_ROLE_KEY from Supabase Settings -> API, then restart backend.",
        });
    }

    // Fetch product first so we can also cleanup images from Storage (best-effort).
    const { data: existing, error: existingError } = await supabaseAdmin
        .from("products")
        .select("*")
        .eq("id", id)
        .maybeSingle();

    if (existingError) {
        return res.status(400).json(existingError);
    }

    if (!existing) {
        return res.status(404).json({ error: "Product not found" });
    }

    // If orders reference this product, delete them first so product delete doesn't fail.
    // Note: this removes order history for that product.
    const { error: ordersDeleteError } = await supabaseAdmin
        .from("orders")
        .delete()
        .eq("product_id", id);

    if (ordersDeleteError) {
        return res.status(400).json(ordersDeleteError);
    }

    const { data: deleted, error: deleteError } = await supabaseAdmin
        .from("products")
        .delete()
        .eq("id", id)
        .select("*")
        .maybeSingle();

    if (deleteError) {
        return res.status(400).json(deleteError);
    }

    // Best-effort: remove stored images if they belong to our bucket.
    try {
        const bucket = getBucketName();
        const prefix = `/storage/v1/object/public/${bucket}/`;
        const urls = [existing.image1, existing.image2, existing.image3, existing.image4].filter(Boolean);
        const objectPaths = urls
            .map((u) => {
                const idx = String(u).indexOf(prefix);
                if (idx === -1) return null;
                return String(u).slice(idx + prefix.length);
            })
            .filter(Boolean);

        const uniquePaths = Array.from(new Set(objectPaths));
        if (uniquePaths.length) {
            await supabaseAdmin.storage.from(bucket).remove(uniquePaths);
        }
    } catch (e) {
        // Ignore storage cleanup errors so DB delete still succeeds.
        console.warn("[storage] Cleanup failed:", e?.message || e);
    }

    return res.json({ ok: true, deleted: deleted || existing });
});

// 👉 CREATE ORDER (COD)
app.post("/orders", async (req, res) => {
    const {
        productId,
        size,
        currency,
        unitPrice,
        fullName,
        email,
        phone,
        address,
        city,
        state,
        pincode,
        paymentMethod,
    } = req.body || {};

    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint:
                "Create backend/.env (see backend/.env.example) and set SUPABASE_SERVICE_ROLE_KEY from Supabase Settings -> API, then restart backend.",
        });
    }

    if ((paymentMethod || "").toUpperCase() !== "COD") {
        return res.status(400).json({ error: "Only COD is supported right now" });
    }

    const parsedProductId = typeof productId === "string" ? Number(productId) : productId;
    if (Number.isNaN(parsedProductId)) {
        return res.status(400).json({ error: "Invalid productId" });
    }

    if (!size || !String(size).trim()) {
        return res.status(400).json({ error: "Missing required field: size" });
    }

    const required = {
        fullName,
        phone,
        address,
        city,
        state,
        pincode,
    };

    const missing = Object.entries(required)
        .filter(([, v]) => !v || !String(v).trim())
        .map(([k]) => k);

    if (missing.length) {
        return res.status(400).json({ error: `Missing required fields: ${missing.join(", ")}` });
    }

    const { data: product, error: productError } = await supabasePublic
        .from("products")
        .select("*")
        .eq("id", parsedProductId)
        .maybeSingle();

    if (productError) {
        return res.status(400).json(productError);
    }

    if (!product) {
        return res.status(404).json({ error: "Product not found" });
    }

    const normalizedCurrency = String(currency || "").toUpperCase() === "USD" ? "USD" : "INR";
    const requestedUnitPrice = parseNumberOrNull(unitPrice);
    const productInr = parseNumberOrNull(product.price_inr ?? product.price);
    const productUsd = parseNumberOrNull(product.price_usd);
    const derivedUnitPrice = normalizedCurrency === "USD" ? productUsd : productInr;
    const finalUnitPrice = requestedUnitPrice !== null ? requestedUnitPrice : derivedUnitPrice;

    if (finalUnitPrice === null) {
        return res.status(400).json({ error: "Product price missing for selected currency" });
    }

    // Optional: if the customer is logged in on frontend, it can send a bearer token.
    // We use it to associate the order with that customer.
    let customerUserId = null;
    const customerToken = getBearerToken(req);
    if (customerToken) {
        const { data: userData, error: userError } = await supabasePublic.auth.getUser(customerToken);
        if (userError || !userData?.user) {
            return res.status(401).json({ error: "Invalid or expired customer token" });
        }
        customerUserId = userData.user.id;
    }

    const orderRow = {
        product_id: product.id,
        product_name: product.name,
        product_price: finalUnitPrice,
        size: String(size).trim(),
        customer_name: String(fullName).trim(),
        email: email ? String(email).trim() : null,
        phone: String(phone).trim(),
        address: String(address).trim(),
        city: String(city).trim(),
        state: String(state).trim(),
        pincode: String(pincode).trim(),
        payment_method: "COD",
        status: "pending",
        amount: finalUnitPrice,
        currency: normalizedCurrency,
    };

    if (customerUserId) {
        orderRow.customer_user_id = customerUserId;
    }

    const fallbackOrderRow = { ...orderRow };
    delete fallbackOrderRow.currency;
    delete fallbackOrderRow.customer_user_id;

    const { data, error } = await insertWithFallback("orders", orderRow, fallbackOrderRow);
    if (error) return res.status(400).json(error);
    return res.status(201).json({ ok: true, orderId: data?.id, order: data });
});

// 👉 CUSTOMER: order history (requires customer login)
app.get("/customer/orders", requireCustomer, async (req, res) => {
    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint:
                "Set SUPABASE_SERVICE_ROLE_KEY in backend/.env and restart backend.",
        });
    }

    try {
        const user = req.customer;
        const userId = user.id;
        const email = user.email ? String(user.email).trim().toLowerCase() : "";
        const emailConfirmed = !!user.email_confirmed_at;

        let q = supabaseAdmin
            .from("orders")
            .select("*")
            .order("created_at", { ascending: false });

        // Always include orders linked to user_id.
        // Optionally include older guest orders by email, but only if email is confirmed.
        if (email && emailConfirmed) {
            q = q.or(`customer_user_id.eq.${userId},and(customer_user_id.is.null,email.eq.${email})`);
        } else {
            q = q.eq("customer_user_id", userId);
        }

        const { data, error } = await q;
        if (error) return res.status(400).json({ error: error.message || "Failed to load orders" });

        const withTracking = await attachTrackingUpdates(data || []);
        return res.json({ ok: true, orders: withTracking || [] });
    } catch (e) {
        return res.status(500).json({ error: e?.message || "Failed to load orders" });
    }
});

// 👉 ADMIN: list orders (for tracking updates panel)
app.get("/admin/orders", requireAdmin, async (req, res) => {
    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint: "Set SUPABASE_SERVICE_ROLE_KEY in backend/.env and restart backend.",
        });
    }

    const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 500);
    try {
        const { data, error } = await supabaseAdmin
            .from("orders")
            .select("*")
            .order("created_at", { ascending: false })
            .limit(limit);

        if (error) return res.status(400).json({ error: error.message || "Failed to load orders" });
        const withTracking = await attachTrackingUpdates(data || []);
        return res.json({ ok: true, orders: withTracking || [] });
    } catch (e) {
        return res.status(500).json({ error: e?.message || "Failed to load orders" });
    }
});

// 👉 ADMIN: update tracking fields on an order
app.patch("/admin/orders/:id/tracking", requireAdmin, async (req, res) => {
    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint: "Set SUPABASE_SERVICE_ROLE_KEY in backend/.env and restart backend.",
        });
    }

    const orderId = req.params.id;
    if (!/^\d+$/.test(String(orderId))) {
        return res.status(400).json({ error: "Invalid order id" });
    }
    const body = req.body || {};

    const patch = {
        estimated_delivery_at: parseDateTimeOrNull(body.estimatedDeliveryAt),
        picked_up_from: body.pickedUpFrom !== undefined ? (String(body.pickedUpFrom || "").trim() || null) : undefined,
        picked_up_at: parseDateTimeOrNull(body.pickedUpAt),
        out_for_delivery: body.outForDelivery === undefined ? undefined : !!body.outForDelivery,
        out_for_delivery_at: parseDateTimeOrNull(body.outForDeliveryAt),
        delivered_at: parseDateTimeOrNull(body.deliveredAt),
    };

    // Remove undefined keys so we don't overwrite fields accidentally.
    Object.keys(patch).forEach((k) => {
        if (patch[k] === undefined) delete patch[k];
    });

    try {
        const { data: updated, error } = await supabaseAdmin
            .from("orders")
            .update(patch)
            .eq("id", orderId)
            .select("*")
            .maybeSingle();

        if (error) {
            if (isMissingColumnError(error)) {
                return res.status(400).json({
                    error: error.message,
                    hint: "Run backend/supabase-orders-returns.sql in Supabase SQL Editor to add tracking columns.",
                });
            }
            return res.status(400).json({ error: error.message || "Failed to update tracking" });
        }

        return res.json({ ok: true, order: updated || null });
    } catch (e) {
        return res.status(500).json({ error: e?.message || "Failed to update tracking" });
    }
});

// 👉 ADMIN: add a "received at" location update (multiple times)
app.post("/admin/orders/:id/tracking/received", requireAdmin, async (req, res) => {
    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint: "Set SUPABASE_SERVICE_ROLE_KEY in backend/.env and restart backend.",
        });
    }

    const orderId = req.params.id;
    if (!/^\d+$/.test(String(orderId))) {
        return res.status(400).json({ error: "Invalid order id" });
    }
    const location = req.body?.location ? String(req.body.location).trim() : "";
    const note = req.body?.note ? String(req.body.note).trim() : "";
    const createdAt = parseDateTimeOrNull(req.body?.receivedAt);

    if (!location) return res.status(400).json({ error: "location is required" });

    const row = {
        order_id: orderId,
        location,
        note: note || null,
    };
    if (createdAt) row.created_at = createdAt;

    try {
        const { data, error } = await supabaseAdmin
            .from("order_tracking_updates")
            .insert([row])
            .select("id,order_id,location,note,created_at")
            .single();

        if (error) {
            if (isMissingColumnError(error)) {
                return res.status(400).json({
                    error: error.message,
                    hint: "Run backend/supabase-orders-returns.sql in Supabase SQL Editor to create order_tracking_updates table.",
                });
            }
            return res.status(400).json({ error: error.message || "Failed to add tracking update" });
        }

        return res.status(201).json({ ok: true, update: data || null });
    } catch (e) {
        return res.status(500).json({ error: e?.message || "Failed to add tracking update" });
    }
});

// 👉 ADMIN: update order status (so admin panel can manage orders without opening Supabase)
app.patch("/admin/orders/:id/status", requireAdmin, async (req, res) => {
    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint: "Set SUPABASE_SERVICE_ROLE_KEY in backend/.env and restart backend.",
        });
    }

    const orderId = req.params.id;
    if (!/^\d+$/.test(String(orderId))) {
        return res.status(400).json({ error: "Invalid order id" });
    }

    const raw = req.body?.status === undefined ? "" : String(req.body.status);
    const status = raw.trim().toLowerCase();
    const allowed = new Set(["pending", "confirmed", "shipped", "delivered", "cancelled", "rto"]);
    if (!allowed.has(status)) {
        return res.status(400).json({
            error: "Invalid status",
            allowed: Array.from(allowed),
        });
    }

    try {
        const patch = { status };
        // Convenience: if marked delivered, set delivered_at if available.
        if (status === "delivered") {
            patch.delivered_at = new Date().toISOString();
        }

        const { data: updated, error } = await supabaseAdmin
            .from("orders")
            .update(patch)
            .eq("id", orderId)
            .select("*")
            .maybeSingle();

        if (error) {
            if (isMissingColumnError(error)) {
                // delivered_at might not exist yet; retry without it.
                const { data: updated2, error: error2 } = await supabaseAdmin
                    .from("orders")
                    .update({ status })
                    .eq("id", orderId)
                    .select("*")
                    .maybeSingle();
                if (error2) return res.status(400).json({ error: error2.message || "Failed to update status" });
                return res.json({ ok: true, order: updated2 || null });
            }
            return res.status(400).json({ error: error.message || "Failed to update status" });
        }

        return res.json({ ok: true, order: updated || null });
    } catch (e) {
        return res.status(500).json({ error: e?.message || "Failed to update status" });
    }
});

// 👉 ADMIN: delete an order (for removing fake/test orders)
app.delete("/admin/orders/:id", requireAdmin, async (req, res) => {
    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint: "Set SUPABASE_SERVICE_ROLE_KEY in backend/.env and restart backend.",
        });
    }

    const orderId = req.params.id;
    if (!/^\d+$/.test(String(orderId))) {
        return res.status(400).json({ error: "Invalid order id" });
    }

    try {
        const { data: deleted, error } = await supabaseAdmin
            .from("orders")
            .delete()
            .eq("id", orderId)
            .select("id")
            .maybeSingle();

        if (error) {
            return res.status(400).json({ error: error.message || "Failed to delete order" });
        }

        if (!deleted) {
            return res.status(404).json({ error: "Order not found" });
        }

        return res.json({ ok: true, deletedId: deleted.id });
    } catch (e) {
        return res.status(500).json({ error: e?.message || "Failed to delete order" });
    }
});

// 👉 ADMIN: update manual costs on an order (delivery/packing/ads/rto)
app.patch("/admin/orders/:id/costs", requireAdmin, async (req, res) => {
    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint: "Set SUPABASE_SERVICE_ROLE_KEY in backend/.env and restart backend.",
        });
    }

    const orderId = req.params.id;
    if (!/^\d+$/.test(String(orderId))) {
        return res.status(400).json({ error: "Invalid order id" });
    }

    const body = req.body || {};
    const deliveryCostRaw = body.deliveryCost;
    const packingCostRaw = body.packingCost;
    const adsCostRaw = body.adsCost;
    const rtoCostRaw = body.rtoCost;

    const patch = {
        delivery_cost: deliveryCostRaw === undefined ? undefined : parseNumberOrNull(deliveryCostRaw),
        packing_cost: packingCostRaw === undefined ? undefined : parseNumberOrNull(packingCostRaw),
        ads_cost: adsCostRaw === undefined ? undefined : parseNumberOrNull(adsCostRaw),
        rto_cost: rtoCostRaw === undefined ? undefined : parseNumberOrNull(rtoCostRaw),
    };

    Object.keys(patch).forEach((k) => {
        if (patch[k] === undefined) delete patch[k];
    });

    const vals = [patch.delivery_cost, patch.packing_cost, patch.ads_cost, patch.rto_cost].filter((v) => v !== undefined);
    for (const v of vals) {
        if (v !== null && (!Number.isFinite(v) || v < 0)) {
            return res.status(400).json({ error: "Costs must be non-negative numbers (or empty)" });
        }
    }

    if (Object.keys(patch).length === 0) {
        return res.status(400).json({ error: "No fields to update" });
    }

    const fallbackPatch = { ...patch };
    delete fallbackPatch.delivery_cost;
    delete fallbackPatch.packing_cost;
    delete fallbackPatch.ads_cost;
    delete fallbackPatch.rto_cost;

    const result = await updateWithFallback(
        "orders",
        patch,
        { id: orderId },
        fallbackPatch
    );

    const { data: updated, error } = result;
    if (error) {
        if (isMissingColumnError(error)) {
            return res.status(400).json({
                error: error.message,
                hint: "Run backend/supabase-orders-costs.sql in Supabase SQL Editor to add cost columns.",
            });
        }
        return res.status(400).json({ error: error.message || "Failed to update costs" });
    }

    const requestedAny = deliveryCostRaw !== undefined || packingCostRaw !== undefined || adsCostRaw !== undefined || rtoCostRaw !== undefined;
    if (requestedAny && result.usedFallback) {
        return res.json({
            ...updated,
            warning: "Order updated, but cost fields were NOT saved (DB missing columns). Run supabase-orders-costs.sql in Supabase SQL editor.",
        });
    }

    return res.json(updated);
});

// 👉 CUSTOMER: request return within 7 days (requires customer login)
app.post("/customer/orders/:id/return", requireCustomer, async (req, res) => {
    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint:
                "Set SUPABASE_SERVICE_ROLE_KEY in backend/.env and restart backend.",
        });
    }

    const orderId = req.params.id;
    const reason = (req.body && req.body.reason) ? String(req.body.reason).trim() : null;

    try {
        const user = req.customer;
        const userId = user.id;
        const email = user.email ? String(user.email).trim().toLowerCase() : "";
        const emailConfirmed = !!user.email_confirmed_at;

        // Load order
        const { data: order, error: loadError } = await supabaseAdmin
            .from("orders")
            .select("*")
            .eq("id", orderId)
            .maybeSingle();

        if (loadError) return res.status(400).json({ error: loadError.message || "Failed to load order" });
        if (!order) return res.status(404).json({ error: "Order not found" });

        const ownsById = order.customer_user_id && String(order.customer_user_id) === String(userId);
        const ownsByEmail = !order.customer_user_id && emailConfirmed && email && String(order.email || "").toLowerCase() === email;
        if (!ownsById && !ownsByEmail) return res.status(403).json({ error: "Not allowed" });

        const createdAt = order.created_at ? new Date(order.created_at) : null;
        if (!createdAt || Number.isNaN(createdAt.getTime())) {
            return res.status(400).json({ error: "Order date missing" });
        }

        const now = new Date();
        const daysMs = 7 * 24 * 60 * 60 * 1000;
        if (now.getTime() - createdAt.getTime() > daysMs) {
            return res.status(400).json({ error: "Return window expired (7 days)" });
        }

        const patch = {
            return_status: "requested",
            return_requested_at: new Date().toISOString(),
            return_reason: reason,
        };

        const { data: updated, error: updateError } = await supabaseAdmin
            .from("orders")
            .update(patch)
            .eq("id", orderId)
            .select("*")
            .maybeSingle();

        if (updateError) {
            if (isMissingColumnError(updateError)) {
                return res.status(400).json({
                    error: updateError.message,
                    hint: "Run backend/supabase-orders-returns.sql in Supabase SQL Editor to add return columns.",
                });
            }
            return res.status(400).json({ error: updateError.message || "Failed to request return" });
        }

        return res.json({ ok: true, order: updated || null });
    } catch (e) {
        return res.status(500).json({ error: e?.message || "Failed to request return" });
    }
});

// 👉 CUSTOMER: get 10% off pay-now offer for a COD order (requires customer login)
app.get("/customer/orders/:id/pay-offer", requireCustomer, async (req, res) => {
    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint: "Set SUPABASE_SERVICE_ROLE_KEY in backend/.env and restart backend.",
        });
    }

    const orderId = req.params.id;

    try {
        const user = req.customer;
        const userId = user.id;
        const email = user.email ? String(user.email).trim().toLowerCase() : "";
        const emailConfirmed = !!user.email_confirmed_at;

        const { data: order, error: loadError } = await supabaseAdmin
            .from("orders")
            .select("*")
            .eq("id", orderId)
            .maybeSingle();

        if (loadError) return res.status(400).json({ error: loadError.message || "Failed to load order" });
        if (!order) return res.status(404).json({ error: "Order not found" });

        const ownsById = order.customer_user_id && String(order.customer_user_id) === String(userId);
        const ownsByEmail = !order.customer_user_id && emailConfirmed && email && String(order.email || "").toLowerCase() === email;
        if (!ownsById && !ownsByEmail) return res.status(403).json({ error: "Not allowed" });

        const currency = order.currency ? String(order.currency).toUpperCase() : "INR";
        const originalAmount = parseNumberOrNull(order.amount);
        if (originalAmount === null || originalAmount <= 0) {
            return res.status(400).json({ error: "Order amount missing" });
        }

        const discountPercent = 10;
        const rawDiscounted = originalAmount * (1 - discountPercent / 100);
        const discountedAmount = currency === "USD"
            ? Math.round(rawDiscounted * 100) / 100
            : Math.round(rawDiscounted);

        return res.json({
            ok: true,
            offer: {
                orderId: order.id,
                discountPercent,
                currency,
                originalAmount,
                discountedAmount,
            },
        });
    } catch (e) {
        return res.status(500).json({ error: e?.message || "Failed to load pay offer" });
    }
});

// -------------------- PAYPAL (USA PAYMENTS) --------------------

const getPayPalBaseUrl = () => {
    const mode = String(process.env.PAYPAL_MODE || "sandbox").toLowerCase();
    return mode === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com";
};

const getPayPalAccessToken = async () => {
    const clientId = process.env.PAYPAL_CLIENT_ID;
    const secret = process.env.PAYPAL_CLIENT_SECRET;
    if (!clientId || !secret) {
        const err = new Error("PayPal not configured");
        err.code = "PAYPAL_NOT_CONFIGURED";
        throw err;
    }

    const baseUrl = getPayPalBaseUrl();
    const auth = Buffer.from(`${clientId}:${secret}`).toString("base64");
    const resp = await axios.post(
        `${baseUrl}/v1/oauth2/token`,
        new URLSearchParams({ grant_type: "client_credentials" }).toString(),
        {
            headers: {
                Authorization: `Basic ${auth}`,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout: 15000,
        }
    );

    return resp.data?.access_token || "";
};

app.get("/paypal/config", (req, res) => {
    const rawClientId = process.env.PAYPAL_CLIENT_ID;
    const clientId = rawClientId ? String(rawClientId).trim() : "";
    const mode = String(process.env.PAYPAL_MODE || "sandbox").toLowerCase();

    // Diagnostics: helps debug "client id missing" without leaking secrets
    const envPath = path.join(__dirname, ".env");
    const envFileExists = fs.existsSync(envPath);
    const rawSecret = process.env.PAYPAL_CLIENT_SECRET;
    const secretPresent = !!(rawSecret && String(rawSecret).trim());

    return res.json({
        ok: true,
        clientId,
        mode,
        diagnostics: {
            envFileExists,
            hasClientId: !!clientId,
            clientIdLength: clientId ? clientId.length : 0,
            hasClientSecret: secretPresent,
            hint: !clientId
                ? "Set PAYPAL_CLIENT_ID in backend/.env and restart backend"
                : !secretPresent
                    ? "Set PAYPAL_CLIENT_SECRET in backend/.env and restart backend"
                    : "OK",
        },
    });
});

const computeUsdTotalFromItems = async (items) => {
    if (!Array.isArray(items) || items.length === 0) {
        return { ok: false, error: "Items missing" };
    }

    const normalized = items
        .map((x) => ({
            productId: typeof x?.productId === "string" ? Number(x.productId) : x?.productId,
            size: String(x?.size || "").trim(),
            qty: Math.max(1, Number(x?.qty) || 1),
        }))
        .filter((x) => !Number.isNaN(x.productId) && x.productId);

    if (normalized.length === 0) {
        return { ok: false, error: "Invalid items" };
    }

    const ids = Array.from(new Set(normalized.map((x) => x.productId)));
    const { data: products, error } = await supabasePublic
        .from("products")
        .select("*")
        .in("id", ids);

    if (error) return { ok: false, error: error.message || "Failed to load products" };
    const map = new Map((products || []).map((p) => [p.id, p]));

    let total = 0;
    for (const item of normalized) {
        const p = map.get(item.productId);
        if (!p) return { ok: false, error: `Product not found: ${item.productId}` };
        const usd = parseNumberOrNull(p.price_usd);
        if (usd === null) return { ok: false, error: `USD price missing for: ${p.name || item.productId}` };
        total += usd * item.qty;
    }

    // PayPal expects 2 decimals string
    const value = (Math.round(total * 100) / 100).toFixed(2);
    return { ok: true, value, items: normalized };
};

app.post("/paypal/create-order", async (req, res) => {
    try {
        const currency = String(req.body?.currency || "USD").toUpperCase();
        if (currency !== "USD") {
            return res.status(400).json({ error: "PayPal is configured for USD only" });
        }

        const items = req.body?.items;
        const computed = await computeUsdTotalFromItems(items);
        if (!computed.ok) return res.status(400).json({ error: computed.error });

        const accessToken = await getPayPalAccessToken();
        const baseUrl = getPayPalBaseUrl();

        const order = await axios.post(
            `${baseUrl}/v2/checkout/orders`,
            {
                intent: "CAPTURE",
                purchase_units: [
                    {
                        amount: {
                            currency_code: "USD",
                            value: computed.value,
                        },
                    },
                ],
            },
            {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    "Content-Type": "application/json",
                },
                timeout: 15000,
            }
        );

        return res.status(201).json({ id: order.data?.id });
    } catch (e) {
        const msg = e?.response?.data?.message || e?.message || "PayPal create order failed";
        const details = e?.response?.data || null;
        const status = e?.response?.status || 500;
        return res.status(status).json({ error: msg, details });
    }
});

app.post("/paypal/capture-order", async (req, res) => {
    const {
        orderID,
        items,
        fullName,
        email,
        phone,
        address,
        city,
        state,
        pincode,
    } = req.body || {};

    if (!supabaseAdmin) {
        return res.status(500).json({
            error: "Server not configured for admin writes",
            hint:
                "Create backend/.env (see backend/.env.example) and set SUPABASE_SERVICE_ROLE_KEY from Supabase Settings -> API, then restart backend.",
        });
    }

    if (!orderID) {
        return res.status(400).json({ error: "Missing orderID" });
    }

    const required = { fullName, phone, address, city, state, pincode };
    const missing = Object.entries(required)
        .filter(([, v]) => !v || !String(v).trim())
        .map(([k]) => k);
    if (missing.length) {
        return res.status(400).json({ error: `Missing required fields: ${missing.join(", ")}` });
    }

    const computed = await computeUsdTotalFromItems(items);
    if (!computed.ok) return res.status(400).json({ error: computed.error });

    // Optional: customer association (same as COD endpoint)
    let customerUserId = null;
    const customerToken = getBearerToken(req);
    if (customerToken) {
        const { data: userData, error: userError } = await supabasePublic.auth.getUser(customerToken);
        if (userError || !userData?.user) {
            return res.status(401).json({ error: "Invalid or expired customer token" });
        }
        customerUserId = userData.user.id;
    }

    try {
        const accessToken = await getPayPalAccessToken();
        const baseUrl = getPayPalBaseUrl();

        const captured = await axios.post(
            `${baseUrl}/v2/checkout/orders/${encodeURIComponent(orderID)}/capture`,
            {},
            {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    "Content-Type": "application/json",
                },
                timeout: 20000,
            }
        );

        const payload = captured.data || {};
        const status = String(payload.status || "").toUpperCase();
        if (status !== "COMPLETED") {
            return res.status(400).json({ error: `PayPal status not completed: ${payload.status || "unknown"}`, details: payload });
        }

        const captureAmount = payload?.purchase_units?.[0]?.payments?.captures?.[0]?.amount;
        const paidValue = Number(captureAmount?.value);
        const expectedValue = Number(computed.value);
        if (!Number.isNaN(paidValue) && !Number.isNaN(expectedValue)) {
            const diff = Math.abs(paidValue - expectedValue);
            if (diff > 0.01) {
                return res.status(400).json({
                    error: "Paid amount mismatch",
                    expected: computed.value,
                    paid: String(captureAmount?.value || ""),
                });
            }
        }

        // Insert orders (one row per qty), similar to COD flow
        const ids = Array.from(new Set(computed.items.map((x) => x.productId)));
        const { data: products, error: productError } = await supabasePublic
            .from("products")
            .select("*")
            .in("id", ids);

        if (productError) return res.status(400).json(productError);
        const map = new Map((products || []).map((p) => [p.id, p]));

        const createdOrders = [];
        for (const item of computed.items) {
            const p = map.get(item.productId);
            if (!p) continue;
            const usd = parseNumberOrNull(p.price_usd);
            if (usd === null) continue;

            for (let i = 0; i < item.qty; i++) {
                const orderRow = {
                    product_id: p.id,
                    product_name: p.name,
                    product_price: usd,
                    size: String(item.size).trim() || "—",
                    customer_name: String(fullName).trim(),
                    email: email ? String(email).trim() : null,
                    phone: String(phone).trim(),
                    address: String(address).trim(),
                    city: String(city).trim(),
                    state: String(state).trim(),
                    pincode: String(pincode).trim(),
                    payment_method: "PAYPAL",
                    status: "paid",
                    amount: usd,
                    currency: "USD",
                };

                if (customerUserId) {
                    orderRow.customer_user_id = customerUserId;
                }

                const fallbackOrderRow = { ...orderRow };
                delete fallbackOrderRow.currency;
                delete fallbackOrderRow.customer_user_id;

                // eslint-disable-next-line no-await-in-loop
                const { data, error } = await insertWithFallback("orders", orderRow, fallbackOrderRow);
                if (error) return res.status(400).json(error);
                createdOrders.push(data);
            }
        }

        const orderIds = createdOrders.map((o) => o?.id).filter(Boolean);
        return res.status(201).json({ ok: true, paypalOrderId: orderID, orders: orderIds });
    } catch (e) {
        const msg = e?.response?.data?.message || e?.message || "PayPal capture failed";
        const details = e?.response?.data || null;
        const status = e?.response?.status || 500;
        return res.status(status).json({ error: msg, details });
    }
});

// SERVER START (SABSE LAST)
const PORT = Number(process.env.PORT) || 5000;
const HOST = "0.0.0.0";

app.listen(PORT, HOST, () => {
    console.log(`Server running on port ${PORT}`);

    // Make sure the product-images bucket is public so product image URLs load.
    // (If SUPABASE_SERVICE_ROLE_KEY is not set, this will just no-op with a warning response.)
    ensureBucketExists(getBucketName()).then((result) => {
        if (!result?.ok) {
            console.warn("[storage] Bucket check failed:", result?.error?.message || result?.error);
        }
    });
});
