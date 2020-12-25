import builtins
async def render_template(request, f, **kwargs):
    # This is a BristleRootShadow (brs) object which basically contains
    if f.__contains__("login.html") or f.__contains__("register.html") or f.__contains__("reset"):
        login_register = True
    else:
        login_register = False
    if request.session.get("csrf") is None:
        form = await Form.from_formdata(request)
    else:
        form = None
        request.session["csrf"] = None
    if request.session.get("status_code") is not None:
        status_code = request.session.get("status_code")
        request.session["status_code"] = None
    else:
        status_code = 200
    base_dict = {'request': request, "username": request.session.get("username"), "brs_list": builtins.brs, "login_register": login_register, "form": form}
    return templates.TemplateResponse(f, {**base_dict, **kwargs}, status_code = status_code)

