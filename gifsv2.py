#!/usr/bin/env python3
import os
import sys
import argparse
from PIL import Image, ImageOps, ImageDraw, ImageFont
import numpy as np

def gif_to_tfx_enhanced(gif_path, output_path, target_width=120, target_height=48):
    """
    Enhanced GIF to TFX conversion with better resolution and dithering
    """
    try:
        # Open the GIF
        gif = Image.open(gif_path)
        frames = []
        
        # Extract all frames
        try:
            while True:
                frame = gif.copy()
                # Convert to RGB if not already
                if frame.mode != 'RGB':
                    frame = frame.convert('RGB')
                frames.append(frame)
                gif.seek(gif.tell() + 1)
        except EOFError:
            pass
        
        print(f"Found {len(frames)} frames in GIF")
        
        with open(output_path, 'w', encoding='utf-8') as tfx_file:
            # Write initial terminal setup
            tfx_file.write('\033c')  # Clear screen
            tfx_file.write('\033[?25l')  # Hide cursor
            
            for frame_idx, frame in enumerate(frames):
                print(f"Processing frame {frame_idx + 1}/{len(frames)}")
                
                # Resize with better algorithm
                frame = resize_enhanced(frame, target_width, target_height * 2)
                
                # Apply Floyd-Steinberg dithering for better color representation
                frame = floyd_steinberg_dithering(frame)
                
                # Convert to numpy array for easier processing
                img_array = np.array(frame)
                height, width, _ = img_array.shape
                
                # Write frame position
                tfx_file.write(f'\033[0;0H')  # Move to top-left
                
                # Process each row individually for better resolution
                for y in range(0, height, 2):
                    if y + 1 >= height:
                        # Last row (single row)
                        for x in range(width):
                            pixel = img_array[y, x]
                            r, g, b = pixel
                            tfx_file.write(f'\033[48;2;{r};{g};{b}m ')  # Space with background color
                        tfx_file.write('\033[0m\n')
                    else:
                        # Process two rows together
                        for x in range(width):
                            top_pixel = img_array[y, x]
                            bottom_pixel = img_array[y + 1, x]
                            
                            top_r, top_g, top_b = top_pixel
                            bottom_r, bottom_g, bottom_b = bottom_pixel
                            
                            # Use different characters based on color similarity
                            if abs(top_r - bottom_r) < 30 and abs(top_g - bottom_g) < 30 and abs(top_b - bottom_b) < 30:
                                # Similar colors - use full block
                                tfx_file.write(f'\033[38;2;{top_r};{top_g};{top_b}m█')
                            else:
                                # Different colors - use half blocks for better resolution
                                tfx_file.write(f'\033[38;2;{top_r};{top_g};{top_b};48;2;{bottom_r};{bottom_g};{bottom_b}m▄')
                        
                        tfx_file.write('\033[0m\n')  # Reset and newline
                
                # Add small delay between frames
                tfx_file.write('\033[0J')  # Clear from cursor to end of screen
                
            # Show cursor at the end
            tfx_file.write('\033[?25h')
            
        print(f"Enhanced TFX file created: {output_path}")
        
    except Exception as e:
        print(f"Error: {e}")
        return False
    
    return True

def resize_enhanced(image, target_width, target_height):
    """
    Higher quality resizing with Lanczos filtering
    """
    img_width, img_height = image.size
    aspect_ratio = img_width / img_height
    
    # Calculate new dimensions
    new_width = target_width
    new_height = int(target_width / aspect_ratio)
    
    if new_height > target_height:
        new_height = target_height
        new_width = int(target_height * aspect_ratio)
    
    # Use higher quality resampling
    resized = image.resize((new_width, new_height), Image.LANCZOS)
    
    # Create a black background and center the image
    if new_width < target_width or new_height < target_height:
        background = Image.new('RGB', (target_width, target_height), (0, 0, 0))
        x_offset = (target_width - new_width) // 2
        y_offset = (target_height - new_height) // 2
        background.paste(resized, (x_offset, y_offset))
        return background
    
    return resized

def floyd_steinberg_dithering(img):
    """
    Apply Floyd-Steinberg dithering to reduce color banding
    """
    img = img.convert('RGB')
    pixels = np.array(img, dtype=float) / 255.0
    height, width, _ = pixels.shape
    
    for y in range(height):
        for x in range(width):
            old_r, old_g, old_b = pixels[y, x]
            
            # Quantize to 256 color space (terminal colors)
            new_r = round(old_r * 5) / 5
            new_g = round(old_g * 5) / 5
            new_b = round(old_b * 5) / 5
            
            pixels[y, x] = [new_r, new_g, new_b]
            
            # Calculate error
            err_r = old_r - new_r
            err_g = old_g - new_g
            err_b = old_b - new_b
            
            # Distribute error to neighboring pixels
            if x + 1 < width:
                pixels[y, x+1] += [err_r * 7/16, err_g * 7/16, err_b * 7/16]
            if y + 1 < height:
                if x - 1 >= 0:
                    pixels[y+1, x-1] += [err_r * 3/16, err_g * 3/16, err_b * 3/16]
                pixels[y+1, x] += [err_r * 5/16, err_g * 5/16, err_b * 5/16]
                if x + 1 < width:
                    pixels[y+1, x+1] += [err_r * 1/16, err_g * 1/16, err_b * 1/16]
    
    # Convert back to 0-255 range
    pixels = np.clip(pixels * 255, 0, 255).astype(np.uint8)
    return Image.fromarray(pixels)

def main():
    parser = argparse.ArgumentParser(description='Convert GIF to enhanced TFX format for terminal display')
    parser.add_argument('input', help='Input GIF file')
    parser.add_argument('output', help='Output TFX file')
    parser.add_argument('--width', type=int, default=120, help='Terminal width (default: 120)')
    parser.add_argument('--height', type=int, default=48, help='Terminal height (default: 48)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found")
        sys.exit(1)
    
    success = gif_to_tfx_enhanced(args.input, args.output, args.width, args.height)
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()