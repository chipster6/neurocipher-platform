#!/usr/bin/env python3
"""
White-Label Branding Manager for AuditHound MSP
Handles custom branding, themes, and UI customization for MSP clients
"""

import logging
import json
import os
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
# import yaml  # Not needed for core functionality
import base64
# from PIL import Image, ImageDraw, ImageFont  # Optional for logo generation
# import colorsys  # Optional for color manipulation

logger = logging.getLogger(__name__)

class BrandingAssetType(Enum):
    """Types of branding assets"""
    LOGO_PRIMARY = "logo_primary"
    LOGO_SECONDARY = "logo_secondary"
    LOGO_ICON = "logo_icon"
    FAVICON = "favicon"
    BACKGROUND = "background"
    PATTERN = "pattern"

class ThemeMode(Enum):
    """Theme modes"""
    LIGHT = "light"
    DARK = "dark"
    AUTO = "auto"

@dataclass
class ColorPalette:
    """Color palette for white-label themes"""
    primary: str = "#1f77b4"
    secondary: str = "#ff7f0e"
    accent: str = "#2ca02c"
    background: str = "#ffffff"
    surface: str = "#f8f9fa"
    text_primary: str = "#212529"
    text_secondary: str = "#6c757d"
    text_light: str = "#ffffff"
    
    # Status colors
    success: str = "#28a745"
    warning: str = "#ffc107"
    error: str = "#dc3545"
    info: str = "#17a2b8"
    
    # Interactive colors
    link: str = "#007bff"
    hover: str = "#0056b3"
    focus: str = "#80bdff"
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary"""
        return {
            "primary": self.primary,
            "secondary": self.secondary,
            "accent": self.accent,
            "background": self.background,
            "surface": self.surface,
            "text_primary": self.text_primary,
            "text_secondary": self.text_secondary,
            "text_light": self.text_light,
            "success": self.success,
            "warning": self.warning,
            "error": self.error,
            "info": self.info,
            "link": self.link,
            "hover": self.hover,
            "focus": self.focus
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'ColorPalette':
        """Create from dictionary"""
        return cls(**data)
    
    def generate_dark_variant(self) -> 'ColorPalette':
        """Generate dark mode variant of the color palette"""
        return ColorPalette(
            primary=self.primary,
            secondary=self.secondary,
            accent=self.accent,
            background="#1a1a1a",
            surface="#2d2d2d",
            text_primary="#ffffff",
            text_secondary="#b0b0b0",
            text_light="#ffffff",
            success=self.success,
            warning=self.warning,
            error=self.error,
            info=self.info,
            link="#4dabf7",
            hover="#339af0",
            focus="#74c0fc"
        )

@dataclass
class Typography:
    """Typography configuration"""
    font_family_primary: str = "Inter, -apple-system, BlinkMacSystemFont, sans-serif"
    font_family_secondary: str = "system-ui, sans-serif"
    font_family_mono: str = "JetBrains Mono, Consolas, monospace"
    
    # Font sizes (in rem)
    size_xs: str = "0.75rem"
    size_sm: str = "0.875rem"
    size_base: str = "1rem"
    size_lg: str = "1.125rem"
    size_xl: str = "1.25rem"
    size_2xl: str = "1.5rem"
    size_3xl: str = "1.875rem"
    size_4xl: str = "2.25rem"
    
    # Font weights
    weight_light: int = 300
    weight_normal: int = 400
    weight_medium: int = 500
    weight_semibold: int = 600
    weight_bold: int = 700
    
    # Line heights
    line_height_tight: float = 1.25
    line_height_normal: float = 1.5
    line_height_relaxed: float = 1.75
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "font_family_primary": self.font_family_primary,
            "font_family_secondary": self.font_family_secondary,
            "font_family_mono": self.font_family_mono,
            "size_xs": self.size_xs,
            "size_sm": self.size_sm,
            "size_base": self.size_base,
            "size_lg": self.size_lg,
            "size_xl": self.size_xl,
            "size_2xl": self.size_2xl,
            "size_3xl": self.size_3xl,
            "size_4xl": self.size_4xl,
            "weight_light": self.weight_light,
            "weight_normal": self.weight_normal,
            "weight_medium": self.weight_medium,
            "weight_semibold": self.weight_semibold,
            "weight_bold": self.weight_bold,
            "line_height_tight": self.line_height_tight,
            "line_height_normal": self.line_height_normal,
            "line_height_relaxed": self.line_height_relaxed
        }

@dataclass
class LayoutConfig:
    """Layout and spacing configuration"""
    # Container widths
    container_sm: str = "640px"
    container_md: str = "768px"
    container_lg: str = "1024px"
    container_xl: str = "1280px"
    container_2xl: str = "1536px"
    
    # Sidebar and navigation
    sidebar_width: str = "280px"
    sidebar_collapsed_width: str = "60px"
    header_height: str = "64px"
    footer_height: str = "60px"
    
    # Spacing scale (in rem)
    space_xs: str = "0.25rem"
    space_sm: str = "0.5rem"
    space_md: str = "1rem"
    space_lg: str = "1.5rem"
    space_xl: str = "2rem"
    space_2xl: str = "3rem"
    
    # Border radius
    radius_sm: str = "4px"
    radius_md: str = "6px"
    radius_lg: str = "8px"
    radius_xl: str = "12px"
    radius_full: str = "50%"
    
    # Shadows
    shadow_sm: str = "0 1px 2px rgba(0, 0, 0, 0.05)"
    shadow_md: str = "0 4px 6px rgba(0, 0, 0, 0.1)"
    shadow_lg: str = "0 10px 15px rgba(0, 0, 0, 0.1)"
    shadow_xl: str = "0 20px 25px rgba(0, 0, 0, 0.1)"
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary"""
        return {
            "container_sm": self.container_sm,
            "container_md": self.container_md,
            "container_lg": self.container_lg,
            "container_xl": self.container_xl,
            "container_2xl": self.container_2xl,
            "sidebar_width": self.sidebar_width,
            "sidebar_collapsed_width": self.sidebar_collapsed_width,
            "header_height": self.header_height,
            "footer_height": self.footer_height,
            "space_xs": self.space_xs,
            "space_sm": self.space_sm,
            "space_md": self.space_md,
            "space_lg": self.space_lg,
            "space_xl": self.space_xl,
            "space_2xl": self.space_2xl,
            "radius_sm": self.radius_sm,
            "radius_md": self.radius_md,
            "radius_lg": self.radius_lg,
            "radius_xl": self.radius_xl,
            "radius_full": self.radius_full,
            "shadow_sm": self.shadow_sm,
            "shadow_md": self.shadow_md,
            "shadow_lg": self.shadow_lg,
            "shadow_xl": self.shadow_xl
        }

@dataclass
class WhiteLabelTheme:
    """Complete white-label theme configuration"""
    name: str
    description: str = ""
    version: str = "1.0.0"
    
    # Branding
    company_name: str = ""
    tagline: str = ""
    
    # Visual identity
    colors: ColorPalette = field(default_factory=ColorPalette)
    colors_dark: Optional[ColorPalette] = None
    typography: Typography = field(default_factory=Typography)
    layout: LayoutConfig = field(default_factory=LayoutConfig)
    
    # Assets
    logo_primary: str = ""
    logo_secondary: str = ""
    logo_icon: str = ""
    favicon: str = ""
    
    # Contact and support
    support_email: str = ""
    support_phone: str = ""
    website_url: str = ""
    documentation_url: str = ""
    
    # Features and customization
    hide_audithound_branding: bool = False
    custom_css: str = ""
    custom_js: str = ""
    footer_text: str = ""
    
    # Theme mode
    default_mode: ThemeMode = ThemeMode.LIGHT
    allow_mode_toggle: bool = True
    
    # Created/updated tracking
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "company_name": self.company_name,
            "tagline": self.tagline,
            "colors": self.colors.to_dict(),
            "colors_dark": self.colors_dark.to_dict() if self.colors_dark else None,
            "typography": self.typography.to_dict(),
            "layout": self.layout.to_dict(),
            "logo_primary": self.logo_primary,
            "logo_secondary": self.logo_secondary,
            "logo_icon": self.logo_icon,
            "favicon": self.favicon,
            "support_email": self.support_email,
            "support_phone": self.support_phone,
            "website_url": self.website_url,
            "documentation_url": self.documentation_url,
            "hide_audithound_branding": self.hide_audithound_branding,
            "custom_css": self.custom_css,
            "custom_js": self.custom_js,
            "footer_text": self.footer_text,
            "default_mode": self.default_mode.value,
            "allow_mode_toggle": self.allow_mode_toggle,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WhiteLabelTheme':
        """Create from dictionary"""
        # Handle nested objects
        if "colors" in data and isinstance(data["colors"], dict):
            data["colors"] = ColorPalette.from_dict(data["colors"])
        
        if "colors_dark" in data and data["colors_dark"]:
            data["colors_dark"] = ColorPalette.from_dict(data["colors_dark"])
        
        if "typography" in data and isinstance(data["typography"], dict):
            data["typography"] = Typography(**data["typography"])
        
        if "layout" in data and isinstance(data["layout"], dict):
            data["layout"] = LayoutConfig(**data["layout"])
        
        # Handle datetime fields
        if isinstance(data.get("created_at"), str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if isinstance(data.get("updated_at"), str):
            data["updated_at"] = datetime.fromisoformat(data["updated_at"])
        
        # Handle enum fields
        if isinstance(data.get("default_mode"), str):
            data["default_mode"] = ThemeMode(data["default_mode"])
        
        return cls(**data)

class WhiteLabelManager:
    """
    White-Label Branding Manager
    Handles theme creation, asset management, and branding customization
    """
    
    def __init__(self, install_dir: str = None):
        """Initialize white-label manager"""
        self.install_dir = Path(install_dir) if install_dir else Path.cwd()
        
        # White-label directories
        self.white_label_dir = self.install_dir / "white-label"
        self.themes_dir = self.white_label_dir / "themes"
        self.assets_dir = self.white_label_dir / "assets"
        self.templates_dir = self.white_label_dir / "templates"
        self.generated_dir = self.white_label_dir / "generated"
        
        # Create directories
        for directory in [self.white_label_dir, self.themes_dir, self.assets_dir, 
                         self.templates_dir, self.generated_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Available themes
        self.themes: Dict[str, WhiteLabelTheme] = {}
        
        # Load existing themes
        self.load_themes()
        
        # Create default theme if none exist
        if not self.themes:
            self.create_default_theme()
        
        logger.info(f"White-label manager initialized with {len(self.themes)} themes")
    
    def load_themes(self):
        """Load all available themes"""
        for theme_file in self.themes_dir.glob("*.json"):
            try:
                with open(theme_file, 'r') as f:
                    theme_data = json.load(f)
                
                theme = WhiteLabelTheme.from_dict(theme_data)
                self.themes[theme.name] = theme
                
            except Exception as e:
                logger.error(f"Failed to load theme {theme_file}: {e}")
    
    def create_default_theme(self):
        """Create default white-label theme"""
        default_theme = WhiteLabelTheme(
            name="default",
            description="Default AuditHound MSP Theme",
            company_name="Your MSP Company",
            tagline="Secure. Compliant. Trusted.",
            support_email="support@yourmsp.com",
            website_url="https://yourmsp.com",
            footer_text="Powered by Your MSP Company - Securing Your Digital Future"
        )
        
        # Generate default assets
        self._generate_default_assets(default_theme)
        
        # Save theme
        self.save_theme(default_theme)
        
        logger.info("Created default white-label theme")
    
    def create_theme(self, name: str, config: Dict[str, Any]) -> WhiteLabelTheme:
        """
        Create new white-label theme
        
        Args:
            name: Theme name
            config: Theme configuration
            
        Returns:
            Created theme
        """
        # Start with default theme
        theme = WhiteLabelTheme(name=name)
        
        # Apply configuration
        for key, value in config.items():
            if hasattr(theme, key):
                setattr(theme, key, value)
        
        # Generate dark mode colors if not provided
        if not theme.colors_dark:
            theme.colors_dark = theme.colors.generate_dark_variant()
        
        # Generate assets if not provided
        if not theme.logo_primary:
            self._generate_logo(theme)
        
        if not theme.favicon:
            self._generate_favicon(theme)
        
        # Save theme
        self.save_theme(theme)
        
        logger.info(f"Created white-label theme: {name}")
        return theme
    
    def update_theme(self, name: str, updates: Dict[str, Any]) -> bool:
        """Update existing theme"""
        theme = self.themes.get(name)
        if not theme:
            return False
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(theme, key):
                setattr(theme, key, value)
        
        theme.updated_at = datetime.now()
        
        # Regenerate assets if needed
        if "colors" in updates or "company_name" in updates:
            self._regenerate_assets(theme)
        
        # Save updated theme
        self.save_theme(theme)
        
        logger.info(f"Updated white-label theme: {name}")
        return True
    
    def save_theme(self, theme: WhiteLabelTheme):
        """Save theme to disk"""
        theme_file = self.themes_dir / f"{theme.name}.json"
        with open(theme_file, 'w') as f:
            json.dump(theme.to_dict(), f, indent=2)
        
        # Add to memory
        self.themes[theme.name] = theme
    
    def get_theme(self, name: str) -> Optional[WhiteLabelTheme]:
        """Get theme by name"""
        return self.themes.get(name)
    
    def list_themes(self) -> List[str]:
        """List all available theme names"""
        return list(self.themes.keys())
    
    def delete_theme(self, name: str) -> bool:
        """Delete theme"""
        if name not in self.themes:
            return False
        
        # Don't delete default theme
        if name == "default":
            logger.warning("Cannot delete default theme")
            return False
        
        # Remove from disk
        theme_file = self.themes_dir / f"{name}.json"
        if theme_file.exists():
            theme_file.unlink()
        
        # Remove assets
        theme_assets_dir = self.assets_dir / name
        if theme_assets_dir.exists():
            shutil.rmtree(theme_assets_dir)
        
        # Remove from memory
        del self.themes[name]
        
        logger.info(f"Deleted white-label theme: {name}")
        return True
    
    def generate_css_theme(self, theme_name: str, mode: ThemeMode = ThemeMode.LIGHT) -> str:
        """Generate CSS theme file"""
        theme = self.get_theme(theme_name)
        if not theme:
            return ""
        
        # Select color palette based on mode
        colors = theme.colors
        if mode == ThemeMode.DARK and theme.colors_dark:
            colors = theme.colors_dark
        
        css_content = f"""
/* White-Label Theme: {theme.name} ({mode.value}) */
/* Generated: {datetime.now().isoformat()} */

:root {{
    /* Brand Colors */
    --brand-primary: {colors.primary};
    --brand-secondary: {colors.secondary};
    --brand-accent: {colors.accent};
    --brand-background: {colors.background};
    --brand-surface: {colors.surface};
    
    /* Text Colors */
    --text-primary: {colors.text_primary};
    --text-secondary: {colors.text_secondary};
    --text-light: {colors.text_light};
    
    /* Status Colors */
    --color-success: {colors.success};
    --color-warning: {colors.warning};
    --color-error: {colors.error};
    --color-info: {colors.info};
    
    /* Interactive Colors */
    --color-link: {colors.link};
    --color-hover: {colors.hover};
    --color-focus: {colors.focus};
    
    /* Typography */
    --font-primary: {theme.typography.font_family_primary};
    --font-secondary: {theme.typography.font_family_secondary};
    --font-mono: {theme.typography.font_family_mono};
    
    /* Font Sizes */
    --text-xs: {theme.typography.size_xs};
    --text-sm: {theme.typography.size_sm};
    --text-base: {theme.typography.size_base};
    --text-lg: {theme.typography.size_lg};
    --text-xl: {theme.typography.size_xl};
    --text-2xl: {theme.typography.size_2xl};
    --text-3xl: {theme.typography.size_3xl};
    --text-4xl: {theme.typography.size_4xl};
    
    /* Layout */
    --sidebar-width: {theme.layout.sidebar_width};
    --header-height: {theme.layout.header_height};
    --footer-height: {theme.layout.footer_height};
    
    /* Spacing */
    --space-xs: {theme.layout.space_xs};
    --space-sm: {theme.layout.space_sm};
    --space-md: {theme.layout.space_md};
    --space-lg: {theme.layout.space_lg};
    --space-xl: {theme.layout.space_xl};
    --space-2xl: {theme.layout.space_2xl};
    
    /* Border Radius */
    --radius-sm: {theme.layout.radius_sm};
    --radius-md: {theme.layout.radius_md};
    --radius-lg: {theme.layout.radius_lg};
    --radius-xl: {theme.layout.radius_xl};
    
    /* Shadows */
    --shadow-sm: {theme.layout.shadow_sm};
    --shadow-md: {theme.layout.shadow_md};
    --shadow-lg: {theme.layout.shadow_lg};
    --shadow-xl: {theme.layout.shadow_xl};
}}

/* Base Styling */
body {{
    font-family: var(--font-primary);
    background-color: var(--brand-background);
    color: var(--text-primary);
    line-height: {theme.typography.line_height_normal};
}}

/* Header Branding */
.main-header {{
    background: linear-gradient(135deg, var(--brand-primary), var(--brand-secondary));
    color: var(--text-light);
    height: var(--header-height);
    box-shadow: var(--shadow-md);
}}

.logo-container {{
    display: flex;
    align-items: center;
    padding: var(--space-md);
}}

.logo-container img {{
    max-height: 40px;
    margin-right: var(--space-md);
}}

.logo-container h1 {{
    color: var(--text-light);
    font-size: var(--text-2xl);
    font-weight: {theme.typography.weight_bold};
    margin: 0;
}}

/* Sidebar Styling */
.stSidebar {{
    background-color: var(--brand-surface);
    border-right: 2px solid var(--brand-primary);
    width: var(--sidebar-width);
}}

.stSidebar .stSelectbox label {{
    color: var(--text-primary);
    font-weight: {theme.typography.weight_medium};
}}

/* Button Styling */
.stButton > button {{
    background: linear-gradient(135deg, var(--brand-primary), var(--brand-secondary));
    color: var(--text-light);
    border: none;
    border-radius: var(--radius-md);
    font-weight: {theme.typography.weight_medium};
    box-shadow: var(--shadow-sm);
    transition: all 0.2s ease;
}}

.stButton > button:hover {{
    background: linear-gradient(135deg, var(--color-hover), var(--brand-secondary));
    box-shadow: var(--shadow-md);
    transform: translateY(-1px);
}}

/* Metric Cards */
.metric-container {{
    background: linear-gradient(135deg, var(--brand-primary), var(--brand-accent));
    color: var(--text-light);
    padding: var(--space-lg);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-md);
    margin: var(--space-sm) 0;
}}

.metric-value {{
    font-size: var(--text-3xl);
    font-weight: {theme.typography.weight_bold};
    line-height: {theme.typography.line_height_tight};
}}

.metric-label {{
    font-size: var(--text-sm);
    opacity: 0.9;
    margin-top: var(--space-xs);
}}

/* Status Indicators */
.status-success {{
    color: var(--color-success);
    font-weight: {theme.typography.weight_medium};
}}

.status-warning {{
    color: var(--color-warning);
    font-weight: {theme.typography.weight_medium};
}}

.status-error {{
    color: var(--color-error);
    font-weight: {theme.typography.weight_medium};
}}

.status-info {{
    color: var(--color-info);
    font-weight: {theme.typography.weight_medium};
}}

/* Compliance Score Cards */
.compliance-score {{
    background: var(--brand-surface);
    border: 2px solid var(--brand-primary);
    border-radius: var(--radius-lg);
    padding: var(--space-lg);
    margin: var(--space-md) 0;
    box-shadow: var(--shadow-sm);
}}

.compliance-score-header {{
    background: linear-gradient(135deg, var(--brand-primary), var(--brand-secondary));
    color: var(--text-light);
    padding: var(--space-md);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-md);
}}

/* Footer */
.footer {{
    background-color: var(--brand-primary);
    color: var(--text-light);
    text-align: center;
    padding: var(--space-lg);
    margin-top: var(--space-2xl);
    border-top: 4px solid var(--brand-secondary);
}}

.footer a {{
    color: var(--text-light);
    text-decoration: none;
    opacity: 0.9;
}}

.footer a:hover {{
    opacity: 1;
    text-decoration: underline;
}}

/* Hide AuditHound branding if requested */
{".audithound-branding { display: none !important; }" if theme.hide_audithound_branding else ""}

/* Custom CSS */
{theme.custom_css}

/* Responsive Design */
@media (max-width: 768px) {{
    :root {{
        --sidebar-width: 100%;
        --header-height: 56px;
    }}
    
    .logo-container h1 {{
        font-size: var(--text-xl);
    }}
    
    .metric-container {{
        padding: var(--space-md);
    }}
    
    .metric-value {{
        font-size: var(--text-2xl);
    }}
}}
"""
        
        return css_content
    
    def generate_streamlit_config(self, theme_name: str) -> Dict[str, Any]:
        """Generate Streamlit configuration for theme"""
        theme = self.get_theme(theme_name)
        if not theme:
            return {}
        
        return {
            "theme": {
                "primaryColor": theme.colors.primary,
                "backgroundColor": theme.colors.background,
                "secondaryBackgroundColor": theme.colors.surface,
                "textColor": theme.colors.text_primary,
                "font": "sans serif"
            }
        }
    
    def _generate_default_assets(self, theme: WhiteLabelTheme):
        """Generate default assets for theme"""
        # Create theme asset directory
        theme_assets_dir = self.assets_dir / theme.name
        theme_assets_dir.mkdir(exist_ok=True)
        
        # Generate logo
        self._generate_logo(theme)
        
        # Generate favicon
        self._generate_favicon(theme)
    
    def _generate_logo(self, theme: WhiteLabelTheme):
        """Generate default logo for theme"""
        try:
            # Try to import PIL for logo generation
            from PIL import Image, ImageDraw, ImageFont
            
            # Create a simple text-based logo
            width, height = 400, 120
            img = Image.new('RGB', (width, height), color=theme.colors.background)
            draw = ImageDraw.Draw(img)
            
            # Try to use a nice font (fallback to default if not available)
            try:
                font_size = 36
                font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", font_size)
            except:
                font = ImageFont.load_default()
            
            # Draw company name
            text = theme.company_name or "Your Company"
            
            # Calculate text position (centered)
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
            x = (width - text_width) // 2
            y = (height - text_height) // 2
            
            # Draw text with primary color
            draw.text((x, y), text, fill=theme.colors.primary, font=font)
            
            # Draw tagline if available
            if theme.tagline:
                try:
                    tagline_font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 16)
                except:
                    tagline_font = ImageFont.load_default()
                
                tagline_bbox = draw.textbbox((0, 0), theme.tagline, font=tagline_font)
                tagline_width = tagline_bbox[2] - tagline_bbox[0]
                tagline_x = (width - tagline_width) // 2
                tagline_y = y + text_height + 10
                
                draw.text((tagline_x, tagline_y), theme.tagline, 
                         fill=theme.colors.text_secondary, font=tagline_font)
            
            # Save logo
            logo_path = self.assets_dir / theme.name / "logo-primary.png"
            img.save(logo_path, "PNG")
            
            theme.logo_primary = str(logo_path.relative_to(self.white_label_dir))
            
            logger.info(f"Generated logo for theme: {theme.name}")
            
        except ImportError:
            # PIL not available, create placeholder
            logger.warning("PIL not available, creating placeholder logo reference")
            theme.logo_primary = f"assets/{theme.name}/logo-primary.png"
            
        except Exception as e:
            logger.error(f"Failed to generate logo for theme {theme.name}: {e}")
            theme.logo_primary = f"assets/{theme.name}/logo-primary.png"
    
    def _generate_favicon(self, theme: WhiteLabelTheme):
        """Generate favicon for theme"""
        try:
            # Try to import PIL for favicon generation
            from PIL import Image, ImageDraw, ImageFont
            
            # Create 32x32 favicon
            size = 32
            img = Image.new('RGB', (size, size), color=theme.colors.primary)
            draw = ImageDraw.Draw(img)
            
            # Draw simple icon (first letter of company name)
            if theme.company_name:
                letter = theme.company_name[0].upper()
                
                try:
                    font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 20)
                except:
                    font = ImageFont.load_default()
                
                # Center the letter
                bbox = draw.textbbox((0, 0), letter, font=font)
                text_width = bbox[2] - bbox[0]
                text_height = bbox[3] - bbox[1]
                x = (size - text_width) // 2
                y = (size - text_height) // 2
                
                draw.text((x, y), letter, fill=theme.colors.text_light, font=font)
            
            # Save favicon
            favicon_path = self.assets_dir / theme.name / "favicon.ico"
            img.save(favicon_path, "ICO", sizes=[(32, 32)])
            
            theme.favicon = str(favicon_path.relative_to(self.white_label_dir))
            
            logger.info(f"Generated favicon for theme: {theme.name}")
            
        except ImportError:
            # PIL not available, create placeholder
            logger.warning("PIL not available, creating placeholder favicon reference")
            theme.favicon = f"assets/{theme.name}/favicon.ico"
            
        except Exception as e:
            logger.error(f"Failed to generate favicon for theme {theme.name}: {e}")
            theme.favicon = f"assets/{theme.name}/favicon.ico"
    
    def _regenerate_assets(self, theme: WhiteLabelTheme):
        """Regenerate assets for updated theme"""
        self._generate_logo(theme)
        self._generate_favicon(theme)
    
    def upload_asset(self, theme_name: str, asset_type: BrandingAssetType, 
                    file_path: str) -> bool:
        """Upload branding asset for theme"""
        theme = self.get_theme(theme_name)
        if not theme:
            return False
        
        try:
            # Create theme asset directory
            theme_assets_dir = self.assets_dir / theme_name
            theme_assets_dir.mkdir(exist_ok=True)
            
            source_path = Path(file_path)
            if not source_path.exists():
                logger.error(f"Asset file not found: {file_path}")
                return False
            
            # Determine destination filename
            if asset_type == BrandingAssetType.LOGO_PRIMARY:
                dest_filename = "logo-primary.png"
                theme.logo_primary = f"assets/{theme_name}/{dest_filename}"
            elif asset_type == BrandingAssetType.LOGO_SECONDARY:
                dest_filename = "logo-secondary.png"
                theme.logo_secondary = f"assets/{theme_name}/{dest_filename}"
            elif asset_type == BrandingAssetType.LOGO_ICON:
                dest_filename = "logo-icon.png"
                theme.logo_icon = f"assets/{theme_name}/{dest_filename}"
            elif asset_type == BrandingAssetType.FAVICON:
                dest_filename = "favicon.ico"
                theme.favicon = f"assets/{theme_name}/{dest_filename}"
            else:
                dest_filename = source_path.name
            
            # Copy file
            dest_path = theme_assets_dir / dest_filename
            shutil.copy2(source_path, dest_path)
            
            # Update theme
            theme.updated_at = datetime.now()
            self.save_theme(theme)
            
            logger.info(f"Uploaded {asset_type.value} for theme: {theme_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to upload asset: {e}")
            return False
    
    def export_theme(self, theme_name: str) -> Dict[str, Any]:
        """Export theme configuration and assets"""
        theme = self.get_theme(theme_name)
        if not theme:
            return {}
        
        export_data = {
            "theme": theme.to_dict(),
            "assets": {},
            "export_timestamp": datetime.now().isoformat(),
            "export_version": "1.0"
        }
        
        # Include asset data (base64 encoded)
        theme_assets_dir = self.assets_dir / theme_name
        if theme_assets_dir.exists():
            for asset_file in theme_assets_dir.iterdir():
                if asset_file.is_file():
                    try:
                        with open(asset_file, 'rb') as f:
                            asset_data = base64.b64encode(f.read()).decode('utf-8')
                        export_data["assets"][asset_file.name] = {
                            "data": asset_data,
                            "filename": asset_file.name,
                            "size": asset_file.stat().st_size
                        }
                    except Exception as e:
                        logger.warning(f"Failed to export asset {asset_file}: {e}")
        
        return export_data
    
    def import_theme(self, export_data: Dict[str, Any]) -> bool:
        """Import theme from export data"""
        try:
            theme_data = export_data["theme"]
            theme = WhiteLabelTheme.from_dict(theme_data)
            
            # Create theme asset directory
            theme_assets_dir = self.assets_dir / theme.name
            theme_assets_dir.mkdir(exist_ok=True)
            
            # Restore assets
            if "assets" in export_data:
                for filename, asset_info in export_data["assets"].items():
                    asset_data = base64.b64decode(asset_info["data"])
                    asset_path = theme_assets_dir / filename
                    
                    with open(asset_path, 'wb') as f:
                        f.write(asset_data)
            
            # Save theme
            self.save_theme(theme)
            
            logger.info(f"Imported white-label theme: {theme.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import theme: {e}")
            return False
    
    def preview_theme(self, theme_name: str) -> str:
        """Generate HTML preview of theme"""
        theme = self.get_theme(theme_name)
        if not theme:
            return ""
        
        css = self.generate_css_theme(theme_name)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Theme Preview: {theme.name}</title>
    <style>
        {css}
        
        .preview-container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: var(--space-lg);
        }}
        
        .preview-section {{
            margin: var(--space-xl) 0;
            padding: var(--space-lg);
            border: 1px solid var(--brand-primary);
            border-radius: var(--radius-lg);
        }}
        
        .preview-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: var(--space-lg);
            margin: var(--space-lg) 0;
        }}
    </style>
</head>
<body>
    <div class="main-header">
        <div class="logo-container">
            <h1>{theme.company_name}</h1>
            <span style="margin-left: var(--space-md); opacity: 0.8;">{theme.tagline}</span>
        </div>
    </div>
    
    <div class="preview-container">
        <h1>Theme Preview: {theme.name}</h1>
        
        <div class="preview-section">
            <h2>Color Palette</h2>
            <div class="preview-grid">
                <div style="background: {theme.colors.primary}; color: white; padding: var(--space-md); border-radius: var(--radius-md);">
                    Primary Color<br><small>{theme.colors.primary}</small>
                </div>
                <div style="background: {theme.colors.secondary}; color: white; padding: var(--space-md); border-radius: var(--radius-md);">
                    Secondary Color<br><small>{theme.colors.secondary}</small>
                </div>
                <div style="background: {theme.colors.accent}; color: white; padding: var(--space-md); border-radius: var(--radius-md);">
                    Accent Color<br><small>{theme.colors.accent}</small>
                </div>
                <div style="background: {theme.colors.background}; color: {theme.colors.text_primary}; padding: var(--space-md); border: 1px solid #ddd; border-radius: var(--radius-md);">
                    Background<br><small>{theme.colors.background}</small>
                </div>
            </div>
        </div>
        
        <div class="preview-section">
            <h2>Status Colors</h2>
            <div class="preview-grid">
                <div class="status-success">✅ Success Message</div>
                <div class="status-warning">⚠️ Warning Message</div>
                <div class="status-error">❌ Error Message</div>
                <div class="status-info">ℹ️ Info Message</div>
            </div>
        </div>
        
        <div class="preview-section">
            <h2>Sample Metrics</h2>
            <div class="preview-grid">
                <div class="metric-container">
                    <div class="metric-value">92.5%</div>
                    <div class="metric-label">Overall Compliance</div>
                </div>
                <div class="metric-container">
                    <div class="metric-value">1,247</div>
                    <div class="metric-label">Total Assets</div>
                </div>
                <div class="metric-container">
                    <div class="metric-value">3</div>
                    <div class="metric-label">Critical Findings</div>
                </div>
            </div>
        </div>
        
        <div class="preview-section">
            <h2>Sample Compliance Score</h2>
            <div class="compliance-score">
                <div class="compliance-score-header">
                    <h3 style="margin: 0;">SOC 2 CC6.1 - Logical Access Controls</h3>
                </div>
                <p>Your organization demonstrates strong logical access controls with multi-factor authentication 
                   enabled across all critical systems.</p>
                <div style="margin-top: var(--space-md);">
                    <span class="status-success">✅ Compliant (90.2%)</span>
                </div>
            </div>
        </div>
    </div>
    
    <div class="footer">
        <p>{theme.footer_text}</p>
        <p>Contact: <a href="mailto:{theme.support_email}">{theme.support_email}</a> | 
           <a href="{theme.website_url}">{theme.website_url}</a></p>
    </div>
</body>
</html>
"""
        
        return html_content

# Factory function
def create_white_label_manager(install_dir: str = None) -> WhiteLabelManager:
    """Create white-label manager instance"""
    return WhiteLabelManager(install_dir)

# Example usage
if __name__ == "__main__":
    # Test white-label manager
    manager = create_white_label_manager()
    
    # Create custom theme
    custom_config = {
        "company_name": "SecureCloud MSP",
        "tagline": "Your Trusted Security Partner",
        "support_email": "support@securecloud.com",
        "website_url": "https://securecloud.com",
        "colors": ColorPalette(
            primary="#2c5aa0",
            secondary="#f39c12",
            accent="#27ae60"
        ),
        "hide_audithound_branding": True
    }
    
    theme = manager.create_theme("securecloud", custom_config)
    print(f"✅ Created custom theme: {theme.name}")
    
    # Generate CSS
    css = manager.generate_css_theme("securecloud")
    print(f"✅ Generated CSS theme ({len(css)} characters)")
    
    # Generate preview
    preview = manager.preview_theme("securecloud")
    print(f"✅ Generated theme preview ({len(preview)} characters)")
    
    print("🎉 White-label manager test completed!")