#!/usr/bin/env python3
"""
Test Cloudflare API Connection for NeuroCipher
"""

import asyncio
import aiohttp
import os
from dotenv import load_dotenv

async def test_cloudflare_connection():
    """Test Cloudflare API connectivity"""
    
    # Load environment variables
    load_dotenv()
    
    api_token = os.getenv("CLOUDFLARE_API_TOKEN")
    account_id = os.getenv("CLOUDFLARE_ACCOUNT_ID")
    
    if not api_token:
        print("❌ CLOUDFLARE_API_TOKEN not found in environment")
        return False
    
    if not account_id:
        print("❌ CLOUDFLARE_ACCOUNT_ID not found in environment")
        return False
    
    print(f"🔑 Testing Cloudflare API connection...")
    print(f"📋 Account ID: {account_id}")
    print(f"🔐 Token: {api_token[:20]}...")
    
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            # Test 1: Verify token
            print("\n🧪 Test 1: Token Verification")
            async with session.get("https://api.cloudflare.com/client/v4/user/tokens/verify") as response:
                if response.status == 200:
                    data = await response.json()
                    print("✅ Token verification successful")
                    print(f"📊 Token status: {data.get('result', {}).get('status', 'unknown')}")
                else:
                    print(f"❌ Token verification failed: {response.status}")
                    return False
            
            # Test 2: List zones
            print("\n🧪 Test 2: List Zones")
            async with session.get("https://api.cloudflare.com/client/v4/zones") as response:
                if response.status == 200:
                    data = await response.json()
                    zones = data.get('result', [])
                    print(f"✅ Found {len(zones)} zones")
                    
                    for zone in zones[:3]:  # Show first 3 zones
                        print(f"🌐 Zone: {zone.get('name')} (ID: {zone.get('id')})")
                        print(f"   Status: {zone.get('status')}")
                        print(f"   Plan: {zone.get('plan', {}).get('name', 'Unknown')}")
                else:
                    print(f"❌ Failed to list zones: {response.status}")
                    return False
            
            # Test 3: Account information
            print("\n🧪 Test 3: Account Information")
            async with session.get(f"https://api.cloudflare.com/client/v4/accounts/{account_id}") as response:
                if response.status == 200:
                    data = await response.json()
                    account = data.get('result', {})
                    print(f"✅ Account: {account.get('name', 'Unknown')}")
                    print(f"📧 Type: {account.get('type', 'Unknown')}")
                else:
                    print(f"❌ Failed to get account info: {response.status}")
                    return False
            
            print("\n🎉 All Cloudflare API tests passed!")
            print("🚀 NeuroCipher is ready for Cloudflare integration!")
            return True
            
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False

async def main():
    """Main test function"""
    print("🧠 NeuroCipher Cloudflare API Test")
    print("=" * 50)
    
    success = await test_cloudflare_connection()
    
    if success:
        print("\n✅ RESULT: Cloudflare integration ready!")
        print("📝 Next steps:")
        print("   1. Restart Claude Code to load MCP servers")
        print("   2. Run: claude mcp list")
        print("   3. Test: neurocipher/security-scan domain=your-domain.com")
    else:
        print("\n❌ RESULT: Cloudflare integration needs attention")
        print("🔧 Check your API token and account ID")

if __name__ == "__main__":
    asyncio.run(main())