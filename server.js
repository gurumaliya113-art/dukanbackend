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
    if (result.error && isMissingColumnError(result.error) && fallbackRow) {
        result = await supabaseAdmin.from(table).insert([fallbackRow]).select("*").single();
    }
    return result;
};

const updateWithFallback = async (table, update, whereEq, fallbackUpdate) => {
    let q = supabaseAdmin.from(table).update(update);
    Object.entries(whereEq || {}).forEach(([k, v]) => {
        q = q.eq(k, v);
    });
    let result = await q.select("*").maybeSingle();

    if (result.error && isMissingColumnError(result.error) && fallbackUpdate) {
        let q2 = supabaseAdmin.from(table).update(fallbackUpdate);
        Object.entries(whereEq || {}).forEach(([k, v]) => {
            q2 = q2.eq(k, v);
        });
        result = await q2.select("*").maybeSingle();
    }

    return result;
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

    const { data: created, error: createError } = await supabaseAdmin.auth.admin.createUser({
        email: String(email).trim().toLowerCase(),
        password: String(password),
        email_confirm: true,
    });

    if (createError || !created?.user) {
        return res.status(400).json({ error: createError?.message || "Failed to create admin user" });
    }

    const userId = created.user.id;
    const userEmail = created.user.email || String(email).trim().toLowerCase();

    const { error: insertError } = await supabaseAdmin
        .from("admin_users")
        .upsert([{ user_id: userId, email: userEmail }], { onConflict: "user_id" });

    if (insertError) {
        return res.status(400).json({ error: insertError.message || "Failed to mark user as admin" });
    }

    return res.status(201).json({ ok: true, userId, email: userEmail });
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

    if (!name || parsedPriceInr === null) {
        return res.status(400).json({
            error: "Missing required fields: name, price_inr (or legacy price)",
            received: Object.keys(req.body || {}),
        });
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
        description: description || null,
        ...imageUrls,
    };

    const fallbackRow = {
        name,
        price: parsedPriceInr,
        description: description || null,
        ...imageUrls,
    };

    const { data, error } = await insertWithFallback("products", row, fallbackRow);
    if (error) return res.status(400).json(error);
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
    const legacyPriceRaw = req.body?.price;

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

    if (description !== undefined) {
        const trimmed = String(description).trim();
        update.description = trimmed ? trimmed : null;
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

    const { data: updated, error: updateError } = await updateWithFallback(
        "products",
        update,
        { id },
        fallbackUpdate
    );

    if (updateError) return res.status(400).json(updateError);
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

    const fallbackOrderRow = { ...orderRow };
    delete fallbackOrderRow.currency;

    const { data, error } = await insertWithFallback("orders", orderRow, fallbackOrderRow);
    if (error) return res.status(400).json(error);
    return res.status(201).json(data);
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

                const fallbackOrderRow = { ...orderRow };
                delete fallbackOrderRow.currency;

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
