#!/usr/bin/env python3
import os
import sys
import argparse
from PIL import Image, ImageOps
import numpy as np

def gif_to_tfx(gif_path, output_path, target_width=80, target_height=24):
    """
    Convert a GIF to TFX format using ▀ characters with proper terminal sizing
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
                
                # Resize to fit terminal (maintaining aspect ratio)
                frame = resize_for_terminal(frame, target_width, target_height * 2)
                
                # Convert to numpy array for easier processing
                img_array = np.array(frame)
                height, width, _ = img_array.shape
                
                # Write frame position
                tfx_file.write(f'\033[0;0H')  # Move to top-left
                
                # Process in pairs of rows (each ▀ character covers 2 rows)
                for y in range(0, height, 2):
                    if y + 1 >= height:
                        break  # Skip if we don't have a pair
                        
                    for x in range(width):
                        # Get top and bottom pixel colors
                        top_pixel = img_array[y, x]
                        bottom_pixel = img_array[y + 1, x]
                        
                        # Convert to 8-bit color codes
                        top_r, top_g, top_b = top_pixel
                        bottom_r, bottom_g, bottom_b = bottom_pixel
                        
                        # Write the ▀ character with both colors
                        tfx_file.write(f'\033[48;2;{bottom_r};{bottom_g};{bottom_b};38;2;{top_r};{top_g};{top_b}m▀')
                    
                    tfx_file.write('\033[0m\n')  # Reset and newline
                
                # Add frame separator and delay
                tfx_file.write('\033[0J')  # Clear from cursor to end of screen
                
            # Show cursor at the end
            tfx_file.write('\033[?25h')
            
        print(f"TFX file created: {output_path}")
        
    except Exception as e:
        print(f"Error: {e}")
        return False
    
    return True

def resize_for_terminal(image, target_width, target_height):
    """
    Resize image to fit terminal while maintaining aspect ratio
    """
    # Calculate aspect ratio preserving dimensions
    img_width, img_height = image.size
    aspect_ratio = img_width / img_height
    
    # Calculate new dimensions
    new_width = target_width
    new_height = int(target_width / aspect_ratio)
    
    if new_height > target_height:
        new_height = target_height
        new_width = int(target_height * aspect_ratio)
    
    # Resize with high-quality filtering
    resized = image.resize((new_width, new_height), Image.LANCZOS)
    
    # Create a black background and center the image
    if new_width < target_width or new_height < target_height:
        background = Image.new('RGB', (target_width, target_height), (0, 0, 0))
        x_offset = (target_width - new_width) // 2
        y_offset = (target_height - new_height) // 2
        background.paste(resized, (x_offset, y_offset))
        return background
    
    return resized

def main():
    parser = argparse.ArgumentParser(description='Convert GIF to TFX format for terminal display')
    parser.add_argument('input', help='Input GIF file')
    parser.add_argument('output', help='Output TFX file')
    parser.add_argument('--width', type=int, default=80, help='Terminal width (default: 80)')
    parser.add_argument('--height', type=int, default=24, help='Terminal height (default: 24)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found")
        sys.exit(1)
    
    success = gif_to_tfx(args.input, args.output, args.width, args.height)
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()