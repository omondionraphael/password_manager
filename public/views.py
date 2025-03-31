from django.shortcuts import render

# Create your views here.
def home(request):
    cards = [
        {"image_url": "one.webp", "title": "Manage Passwords", "description": "Secured with the end-to-end AES-256 encryption."},
        {"image_url": "two.jpg", "title": "All In One Place", "description": "Store Credentials, Docs, Bank Cards or IDs."},
        {"image_url": "three.jpeg", "title": "Smart Categories", "description": "Stay Organized and create your own categories"},
    ]
    return render(request, 'public/home.html', {'cards': cards})

def about(request):
    return render(request, 'public/about.html')