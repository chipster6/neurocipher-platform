# NeuroCipher Deployment Guide

## Quick Deploy to neurocipher.io

Your website files are ready! Follow these steps to deploy to Cloudflare Pages:

### Method 1: Direct Upload (Recommended)

1. **Go to Cloudflare Dashboard**
   - Visit: https://dash.cloudflare.com/
   - Log in with your account

2. **Create Pages Project**
   - Click "Pages" in the left sidebar
   - Click "Create application"
   - Click "Upload assets"

3. **Upload Website Files**
   - Upload these files from `/Users/cody/audithound-unified/`:
     - `index.html` (main website)
     - `_headers` (security headers)
     - `_redirects` (URL routing)
     - All `.html` policy files (TERMS_OF_SERVICE.html, etc.)

4. **Configure Domain**
   - After upload, go to "Custom domains" 
   - Add `neurocipher.io` as custom domain
   - Cloudflare will automatically configure DNS

5. **Deploy**
   - Click "Save and Deploy"
   - Your site will be live at neurocipher.io in ~2 minutes

### Method 2: Git Integration

1. **Push to GitHub** (if not already done)
   ```bash
   git add .
   git commit -m "Website ready for deployment"
   git push origin main
   ```

2. **Connect Git Repository**
   - In Cloudflare Pages, click "Connect to Git"
   - Select your neurocipher repository
   - Set build settings:
     - Build command: (leave empty)
     - Build output directory: `/`
   - Click "Save and Deploy"

## Current Website Features

✅ **Correct Pricing Structure**
- Free: 1 scan/month
- Starter: $50/month - 3 scans
- Professional: $150/month - 10 scans  
- Business: $200/month - unlimited scans

✅ **Business Compliance**
- All required business policies
- Customer service contacts
- Legal compliance documentation

✅ **Security Headers**
- CSP, HSTS, XSS protection
- Frame options and content type protection

✅ **Professional Design**
- Mobile responsive
- Modern UI/UX
- Clear call-to-actions

## Next Steps After Deployment

1. **Verify Website**: Visit neurocipher.io to confirm it's live
2. **Test Contact Forms**: Ensure emails reach you
3. **Set up Analytics**: Add Google Analytics if desired
4. **SSL Certificate**: Cloudflare provides automatic SSL
5. **Monitor Performance**: Use Cloudflare analytics

## Your Website URL

Once deployed: **https://neurocipher.io**

## Support

If you need help with deployment:
- Cloudflare Support: https://support.cloudflare.com/
- Or contact: hello@neurocipher.io