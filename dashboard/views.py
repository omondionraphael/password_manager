import json
import base64
from django.shortcuts import render
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from .models import PasswordEntry, Category
from .forms import PasswordEntryForm, CategoryForm
from django.shortcuts import get_object_or_404, redirect
import csv
from django.http import HttpResponse, JsonResponse
import secrets
import string
from django.utils.crypto import get_random_string
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q

# Create your views here.
@login_required
def home(request):
    search_query = request.GET.get("q", "")
    passwords = PasswordEntry.objects.filter(user=request.user)

    if search_query:
        passwords = passwords.filter(
            Q(website__icontains=search_query) | Q(username__icontains=search_query)
        )
    
    context = {
        "total_passwords": passwords.count(),
        "weak_passwords": passwords.filter(strength="weak").count(),
        "reused_passwords": passwords.filter(is_reused=True).count(),
        "recent_passwords": passwords.order_by('-created_at')[:5],
        "passwords": passwords,
        "search_query": search_query,  # Pass query to template
    }

    return render(request, 'dashboard/home.html', context)

@login_required
def passwords(request):
    return render(request, 'dashboard/passwords.html')

@login_required
def categories(request):
    # Retrieve all categories (you might filter them based on user if needed)
    cats = Category.objects.all()
    # Optionally, you could annotate each with its password count, e.g.:
    for cat in cats:
        cat.password_count = cat.password_count()
    return render(request, 'dashboard/categories.html', {'categories': cats})

@login_required
def backup(request):
    return render(request, 'dashboard/backup.html')

@login_required
def view_profile(request):
    return render(request, 'dashboard/profile.html')

@login_required
def logout(request):
    return redirect(reverse('public:home'))

@login_required
def settings(request):
    return render(request, 'dashboard/settings.html')

@login_required
def add_password(request):
    if request.method == "POST":
        form = PasswordEntryForm(request.POST)
        if form.is_valid():
            password_entry = form.save(commit=False)
            password_entry.user = request.user
            password_entry.save()
            return redirect("dashboard:home")
    else:
        form = PasswordEntryForm()
    
    return render(request, "dashboard/add-password.html", {"form": form})

@login_required
def edit_password(request, password_id):
    password_entry = get_object_or_404(PasswordEntry, id=password_id, user=request.user)

    if request.method == "POST":
        form = PasswordEntryForm(request.POST, instance=password_entry)
        if form.is_valid():
            form.save()
            return redirect("dashboard:home")

    else:
        form = PasswordEntryForm(instance=password_entry)

    return render(request, "dashboard/edit-password.html", {"form": form})

@login_required
def delete_password(request, password_id):
    password_entry = get_object_or_404(PasswordEntry, id=password_id, user=request.user)
    
    if request.method == "POST":
        password_entry.delete()
        return redirect("dashboard:home")
    
    return render(request, "dashboard/confirm-delete.html", {"password_entry": password_entry})


@login_required
def verify_master_password(request):
    if request.method == "POST":
        master_password = request.POST.get("master_password")
        if check_password(master_password, request.user.userprofile.master_password_hash):
            request.session["master_authenticated"] = True
            return redirect("dashboard:home")
        else:
            messages.error(request, "Invalid Master Password")
    return render(request, "dashboard/master_password.html")

# export passwords as a secured encrypted file
@login_required
def export_passwords(request):
    passwords = PasswordEntry.objects.filter(user=request.user)
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="passwords_backup.csv"'
    
    writer = csv.writer(response)
    writer.writerow(["Website", "Username", "Encrypted Password"])
    for password in passwords:
        # Export the encrypted_password as a base64-encoded string
        encrypted_str = base64.b64encode(password.encrypted_password).decode('utf-8')
        writer.writerow([password.website, password.username, encrypted_str])
    
    return response

@login_required
def generate_password(request):
    length = int(request.GET.get("length", 16))  # Default length is 16
    include_symbols = request.GET.get("symbols", "true") == "true"
    
    characters = string.ascii_letters + string.digits
    if include_symbols:
        characters += string.punctuation  # Include special characters
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    
    return JsonResponse({"password": password})

# share passwords securely using temporary encrypted links
@login_required
def share_password(request, password_id):
    password_entry = get_object_or_404(PasswordEntry, id=password_id, user=request.user)
    
    # Generate a secure token
    share_token = get_random_string(length=32)
    cache.set(share_token, password_entry.get_password(), timeout=300)  # Expires in 5 minutes
    
    return JsonResponse({"link": f"http://127.0.0.1:8000/dashboard/retrieve/{share_token}/"})

@csrf_exempt
@login_required
def save_generated_password(request):
    if request.method == "POST":
        data = json.loads(request.body)
        new_password = data.get("password")

        if new_password:
            entry = PasswordEntry(user=request.user, website="Generated Password", username="N/A")
            entry.set_password(new_password)  # Encrypt & Save
            entry.save()
            return JsonResponse({"message": "Password saved successfully!"})
    
    return JsonResponse({"message": "Invalid request!"}, status=400)

@login_required
def add_category(request):
    if request.method == "POST":
        form = CategoryForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("dashboard:categories")
    else:
        form = CategoryForm()
    
    return render(request, "dashboard/add-category.html", {"form": form})

@login_required
def category_detail(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    # Show only the passwords for the current user within this category
    passwords = PasswordEntry.objects.filter(user=request.user, category=category)
    context = {
        "category": category,
        "passwords": passwords,
    }
    return render(request, "dashboard/category-detail.html", context)

@login_required
def restore(request):
    if request.method == "POST":
        csv_file = request.FILES.get("backup_file")
        if not csv_file:
            messages.error(request, "No file uploaded.")
            return redirect("dashboard:restore_passwords")
        
        # Read and decode the uploaded file
        decoded_file = csv_file.read().decode("utf-8").splitlines()
        reader = csv.reader(decoded_file)
        header = next(reader, None)  # Skip header row
        
        # For each row, create a new PasswordEntry
        for row in reader:
            if len(row) < 3:
                continue  # Skip invalid rows
            website, username, encrypted_str = row[:3]
            dummy_password = "Restored@123"  # A dummy value that passes validation
            
            entry = PasswordEntry(
                user=request.user,
                website=website,
                username=username,
                password=dummy_password
            )
            try:
                # Override the encrypted_password field with restored data
                entry.encrypted_password = base64.b64decode(encrypted_str)
                entry.save()
            except Exception as e:
                # Log error or skip this row if necessary
                continue
        messages.success(request, "Backup restored successfully!")
        return redirect("dashboard:home")
    
    return render(request, "dashboard/restore.html")