using System;
using Microsoft.AspNetCore.Mvc;
using A07_UTS.Data;
using A07_UTS.Models;
using Microsoft.AspNetCore.Authorization;

namespace A07_UTS.Controllers;

[Authorize]
public class StudentController : Controller
{
    private readonly IStudent _studentData;

    public StudentController(IStudent studentData)
    {
        _studentData = studentData;
    }

    public IActionResult Index()
    {
        var students = _studentData.GetStudents();
        return View(students);
    }

    public IActionResult Create()
    {
        return View();
    }

    [HttpPost]
    public IActionResult Create(Student student)
    {
       try
       {
        _studentData.AddStudent(student);
        return RedirectToAction("Index");
       }
       catch (System.Exception ex)
       {
        ViewBag.Error = ex.Message;
       }
        return View(student);
    }

    public IActionResult Edit()
    {
        return View();
    }

    public IActionResult Delete()
    {
        return View();
    }

}
